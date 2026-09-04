using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Ipc;

namespace Spemcs.Agent.Service;

public sealed class ControlPipeWorker : BackgroundService
{
    /// <summary>
    /// Prefix the management server uses for key ids it derives from the key material itself
    /// (<c>spemcs-&lt;first 32 hex chars of SHA-256(SPKI DER)&gt;</c>). When an id carries this
    /// prefix the agent can check the id against the bytes it was published with, so key
    /// distribution becomes self-validating. Ids without a recognised prefix (older servers,
    /// test fixtures) are accepted without that check.
    /// </summary>
    private const string FingerprintKeyIdPrefix = "spemcs-";

    /// <summary>Prefix marking a server key that exists only in the server's memory.</summary>
    private const string EphemeralKeyIdPrefix = "ephemeral-";

    private const int FingerprintKeyIdChars = 32;

    /// <summary>
    /// How long a successfully fetched keyring is reused before the agent asks again.
    /// <para>
    /// The previous implementation re-fetched on every single policy apply, which put a
    /// synchronous network round-trip in front of exam activation. Caching forever is the other
    /// extreme and is worse: a key revoked mid-exam would not reach the agent until the service
    /// restarted, and revocation is the one signal that has to arrive quickly.
    /// </para>
    /// </summary>
    private static readonly TimeSpan KeyringRefreshInterval = TimeSpan.FromMinutes(5);

    private readonly ILogger<ControlPipeWorker> _log;
    private readonly AgentWorker _agent;
    private readonly IEnforcementStateMachine _enforcement;
    private readonly ITrustedKeyStore _keyStore;
    private readonly IRollbackJournal _journal;
    private readonly IHttpClientFactory _httpFactory;

    /// <summary>Serializes keyring refreshes so concurrent applies cause one fetch, not N.</summary>
    private readonly SemaphoreSlim _keyStoreGate = new(1, 1);

    private bool _revocationsLoadedFromJournal;
    private bool _keyStoreHasKeys;
    private DateTimeOffset _lastKeyringFetchUtc = DateTimeOffset.MinValue;

    public ControlPipeWorker(
        ILogger<ControlPipeWorker> log,
        AgentWorker agent,
        IEnforcementStateMachine enforcement,
        ITrustedKeyStore keyStore,
        IRollbackJournal journal,
        IHttpClientFactory httpFactory)
    {
        _log = log;
        _agent = agent;
        _enforcement = enforcement;
        _keyStore = keyStore;
        _journal = journal;
        _httpFactory = httpFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        _log.LogInformation("Control pipe worker started, listening on {PipeName}", PipeNames.Control);

        // Revocations first, and synchronously. They are read from the local journal, so this
        // works with no network, and it closes the window in which an agent that reboots offline
        // would honour a key that was revoked before the reboot.
        LoadPersistedRevocations();

        // The keyring fetch is network I/O and must not delay the control pipe becoming
        // available. Anything that actually needs a key awaits EnsureKeyStoreInitializedAsync.
        _ = EnsureKeyStoreInitializedAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = PipeProtocol.CreateServer(PipeNames.Control);
                await pipe.WaitForConnectionAsync(stoppingToken);
                var request = await PipeProtocol.ReadAsync(pipe, stoppingToken);
                if (request is null) continue;

                _log.LogInformation("Received control pipe request: {Type}", request.Type);

                switch (request.Type)
                {
                    case MessageTypes.StartExam:
                    {
                        var accepted = await _agent.StartExamAsync(stoppingToken);
                        await PipeProtocol.WriteAsync(pipe, MessageTypes.CommandResult, new CommandResultPayload(accepted, "handled"), stoppingToken);
                        _log.LogInformation("Replied to START_EXAM with accepted={Accepted}", accepted);
                        break;
                    }

                    case MessageTypes.StopExam:
                    {
                        var accepted = await _agent.StopExamAsync(stoppingToken);
                        await PipeProtocol.WriteAsync(pipe, MessageTypes.CommandResult, new CommandResultPayload(accepted, "handled"), stoppingToken);
                        _log.LogInformation("Replied to STOP_EXAM with accepted={Accepted}", accepted);
                        break;
                    }

                    case MessageTypes.ApplyNetworkPolicy:
                    {
                        var p = request.Payload.Deserialize<ApplyNetworkPolicyPayload>();
                        if (p is null || p.SignedMessage is null)
                        {
                            await PipeProtocol.WriteAsync(pipe, MessageTypes.NetworkPolicyResult,
                                new NetworkPolicyResultPayload(false, Guid.Empty, "Failed", "Malformed ApplyNetworkPolicy payload"), stoppingToken);
                            break;
                        }

                        await EnsureKeyStoreInitializedAsync(stoppingToken);

                        var signedMsg = new SignedPolicyMessage(
                            p.SignedMessage.MessageType,
                            p.SignedMessage.ProtocolVersion,
                            p.SignedMessage.RawPolicyJson,
                            p.SignedMessage.SignatureBase64
                        );

                        // The profile mask is NOT part of the signed policy, and the control pipe is
                        // writable by any authenticated user, so it is normalized rather than cast.
                        // See FirewallProfileSet.FromUntrustedWireValue.
                        var targetProfiles = FirewallProfileSet.FromUntrustedWireValue(p.TargetProfiles, out var profileAnomaly);
                        if (profileAnomaly is not null)
                        {
                            _log.LogError("ApplyNetworkPolicy for session {SessionId}: {Anomaly}", p.SessionId, profileAnomaly);
                        }

                        var actResult = await _enforcement.ActivateAsync(
                            p.SessionId,
                            signedMsg,
                            p.ExamId,
                            targetProfiles,
                            cancellationToken: stoppingToken);

                        var installedCount = _journal.GetSession(p.SessionId)?.AppliedRuleNames?.Count ?? 0;

                        var resPayload = new NetworkPolicyResultPayload(
                            actResult.Success,
                            actResult.SessionId,
                            actResult.State.ToString(),
                            actResult.FailureReason,
                            installedCount
                        );

                        await PipeProtocol.WriteAsync(pipe, MessageTypes.NetworkPolicyResult, resPayload, stoppingToken);
                        _log.LogInformation("Replied to ApplyNetworkPolicy: Success={Success}, State={State}, Reason={Reason}, Rules={Count}",
                            actResult.Success, actResult.State, actResult.FailureReason, installedCount);
                        break;
                    }

                    case MessageTypes.UpdateNetworkPolicy:
                    {
                        var p = request.Payload.Deserialize<ApplyNetworkPolicyPayload>();
                        if (p is null || p.SignedMessage is null)
                        {
                            await PipeProtocol.WriteAsync(pipe, MessageTypes.NetworkPolicyResult,
                                new NetworkPolicyResultPayload(false, Guid.Empty, "Failed", "Malformed UpdateNetworkPolicy payload"), stoppingToken);
                            break;
                        }

                        await EnsureKeyStoreInitializedAsync(stoppingToken);

                        var signedMsg = new SignedPolicyMessage(
                            p.SignedMessage.MessageType,
                            p.SignedMessage.ProtocolVersion,
                            p.SignedMessage.RawPolicyJson,
                            p.SignedMessage.SignatureBase64
                        );

                        var updResult = await _enforcement.UpdatePolicyAsync(signedMsg, cancellationToken: stoppingToken);

                        var installedCount = _journal.GetSession(p.SessionId)?.AppliedRuleNames?.Count ?? 0;

                        var resPayload = new NetworkPolicyResultPayload(
                            updResult.Success,
                            updResult.SessionId,
                            updResult.Success ? EnforcementState.Active.ToString() : EnforcementState.Failed.ToString(),
                            updResult.FailureReason,
                            installedCount
                        );

                        await PipeProtocol.WriteAsync(pipe, MessageTypes.NetworkPolicyResult, resPayload, stoppingToken);
                        _log.LogInformation("Replied to UpdateNetworkPolicy: Success={Success}, NewVersion={Version}, Reason={Reason}",
                            updResult.Success, updResult.NewVersion, updResult.FailureReason);
                        break;
                    }

                    case MessageTypes.RemoveNetworkPolicy:
                    {
                        var p = request.Payload.Deserialize<RemoveNetworkPolicyPayload>();
                        if (p is null)
                        {
                            await PipeProtocol.WriteAsync(pipe, MessageTypes.NetworkPolicyResult,
                                new NetworkPolicyResultPayload(false, Guid.Empty, "Failed", "Malformed RemoveNetworkPolicy payload"), stoppingToken);
                            break;
                        }

                        var deactResult = await _enforcement.DeactivateAsync(p.SessionId, p.Reason ?? "Exam stopped", stoppingToken);

                        var resPayload = new NetworkPolicyResultPayload(
                            deactResult.Success,
                            deactResult.SessionId,
                            deactResult.State.ToString(),
                            deactResult.FailureReason,
                            0
                        );

                        await PipeProtocol.WriteAsync(pipe, MessageTypes.NetworkPolicyResult, resPayload, stoppingToken);
                        _log.LogInformation("Replied to RemoveNetworkPolicy: Success={Success}, State={State}", deactResult.Success, deactResult.State);
                        break;
                    }

                    default:
                    {
                        _log.LogWarning("Unrecognized request type: {Type}", request.Type);
                        await PipeProtocol.WriteAsync(pipe, MessageTypes.CommandResult,
                            new CommandResultPayload(false, "UnknownCommand", $"Unknown type: {request.Type}"), stoppingToken);
                        break;
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Control pipe request exception.");
                await Task.Delay(200, stoppingToken);
            }
        }
    }

    /// <summary>
    /// Makes sure the trusted key store reflects the management server's current keyring.
    /// </summary>
    /// <remarks>
    /// Safe to await on every policy apply: it returns without doing any work while a recent
    /// fetch is still fresh, and only one caller at a time is allowed through the gate.
    /// </remarks>
    private async Task EnsureKeyStoreInitializedAsync(CancellationToken ct)
    {
        if (IsKeyringFresh())
        {
            return;
        }

        try
        {
            await _keyStoreGate.WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        try
        {
            // Another caller may have refreshed while this one waited on the gate.
            if (IsKeyringFresh())
            {
                return;
            }

            LoadPersistedRevocations();

            var client = _httpFactory.CreateClient("BackendApi");

            // The keyring endpoint is preferred because it also carries retired keys (needed to
            // verify a policy issued before the last rotation) and revocations. The single-key
            // endpoint is the fallback for a server that predates it.
            var loaded = await TryLoadKeyringAsync(client, ct).ConfigureAwait(false);
            if (!loaded)
            {
                loaded = await TryLoadActiveKeyOnlyAsync(client, ct).ConfigureAwait(false);
            }

            if (loaded)
            {
                // Only a success advances the clock. A failed fetch deliberately leaves the
                // timestamp alone so the next apply retries instead of waiting out the interval.
                _lastKeyringFetchUtc = DateTimeOffset.UtcNow;
            }
            else if (_keyStoreHasKeys)
            {
                _log.LogWarning(
                    "Could not refresh the signing keyring from the management server. Continuing " +
                    "with the {Count} key(s) already trusted; a revocation published since the last " +
                    "successful fetch would not be known yet.",
                    _keyStore.GetActiveKeyIds().Count);
            }
            else
            {
                _log.LogError(
                    "No policy signing key could be obtained from the management server. Policy " +
                    "verification will fail closed and no exam can be activated on this endpoint.");
            }
        }
        finally
        {
            _keyStoreGate.Release();
        }
    }

    private bool IsKeyringFresh()
        => _keyStoreHasKeys && (DateTimeOffset.UtcNow - _lastKeyringFetchUtc) < KeyringRefreshInterval;

    /// <summary>
    /// Reinstates revocations recorded by an earlier run of the service.
    /// </summary>
    /// <remarks>
    /// Revocation has to be sticky across restarts and across the server changing its mind: once
    /// a key is known to be compromised, an agent must keep refusing it even while offline, and
    /// even if the server later stops listing it.
    /// </remarks>
    private void LoadPersistedRevocations()
    {
        if (_revocationsLoadedFromJournal)
        {
            return;
        }

        try
        {
            var revoked = _journal.GetRevokedKeys();
            foreach (var keyId in revoked)
            {
                if (string.IsNullOrWhiteSpace(keyId)) continue;
                _keyStore.RevokeKey(keyId, "Revoked before this agent restarted (local journal)");
            }

            _revocationsLoadedFromJournal = true;
            if (revoked.Count > 0)
            {
                _log.LogWarning(
                    "Reloaded {Count} revoked signing key id(s) from the local journal; policies " +
                    "signed by them stay rejected.", revoked.Count);
            }
        }
        catch (Exception ex)
        {
            // Left unflagged so the next refresh retries. A server fetch that succeeds will
            // supply the authoritative revocation list anyway; the gap this leaves is narrow -
            // the journal unreadable AND the server having forgotten a revocation it published.
            _log.LogError(
                "Could not read persisted signing key revocations ({Message}). Will retry on the " +
                "next keyring refresh.", ex.Message);
        }
    }

    private async Task<bool> TryLoadKeyringAsync(HttpClient client, CancellationToken ct)
    {
        JsonElement doc;
        try
        {
            doc = await client
                .GetFromJsonAsync<JsonElement>("api/policies/signing-key/keyring", ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning("Could not fetch the signing keyring: {Message}", ex.Message);
            return false;
        }

        if (doc.ValueKind != JsonValueKind.Object
            || !doc.TryGetProperty("keys", out var keysProp)
            || keysProp.ValueKind != JsonValueKind.Array)
        {
            _log.LogWarning("The signing keyring response was not in the expected shape.");
            return false;
        }

        if (doc.TryGetProperty("ephemeral", out var ephemeral) && ephemeral.ValueKind == JsonValueKind.True)
        {
            _log.LogError(
                "The management server is using an EPHEMERAL policy signing key. Every policy it " +
                "signs stops verifying the moment that server restarts, which shows up here as an " +
                "exam that cannot start. The server needs a persistent signing key configured.");
        }

        var registered = 0;

        foreach (var entry in keysProp.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object) continue;

            var keyId = ReadString(entry, "key_id");
            var pem = ReadString(entry, "public_key_pem");

            // No id or no material means no registration. The previous implementation
            // substituted a hardcoded "dev-key-1" when key_id was absent, which bound whatever
            // key the server returned to an id no legitimate policy would carry - producing a
            // signature failure (i.e. "forged") for what was really a protocol mismatch.
            if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(pem))
            {
                _log.LogWarning("Skipped a keyring entry with no usable key_id/public_key_pem pair.");
                continue;
            }

            var isRevoked = string.Equals(ReadString(entry, "state"), "revoked", StringComparison.OrdinalIgnoreCase);
            if (TryRegisterKey(keyId!, pem!, isRevoked, ReadString(entry, "revocation_reason")))
            {
                registered++;
            }
        }

        // Applied separately from the entries above so that an id listed as revoked is still
        // refused even when the server no longer publishes its public key.
        if (doc.TryGetProperty("revoked_key_ids", out var revokedIds) && revokedIds.ValueKind == JsonValueKind.Array)
        {
            foreach (var idElement in revokedIds.EnumerateArray())
            {
                if (idElement.ValueKind != JsonValueKind.String) continue;
                var keyId = idElement.GetString();
                if (string.IsNullOrWhiteSpace(keyId)) continue;
                MarkRevoked(keyId!, null);
            }
        }

        if (registered == 0)
        {
            _log.LogError("The management server published a keyring containing no usable signing key.");
            return false;
        }

        _keyStoreHasKeys = true;

        var activeId = ReadString(doc, "active_key_id");
        _log.LogInformation(
            "Trusted key store synchronised: {Registered} key(s) registered, {Revoked} revoked, " +
            "active key '{ActiveKeyId}'.",
            registered, _keyStore.GetRevokedKeyIds().Count, activeId ?? "(unreported)");

        if (!string.IsNullOrWhiteSpace(activeId)
            && activeId!.StartsWith(EphemeralKeyIdPrefix, StringComparison.Ordinal))
        {
            _log.LogError(
                "Active signing key '{ActiveKeyId}' is an in-memory server key and will not " +
                "survive a management server restart.", activeId);
        }

        return true;
    }

    /// <summary>Fallback for a management server that only exposes its active key.</summary>
    private async Task<bool> TryLoadActiveKeyOnlyAsync(HttpClient client, CancellationToken ct)
    {
        JsonElement doc;
        try
        {
            doc = await client
                .GetFromJsonAsync<JsonElement>("api/policies/signing-key/public", ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning("Could not fetch the active signing key: {Message}", ex.Message);
            return false;
        }

        if (doc.ValueKind != JsonValueKind.Object) return false;

        var keyId = ReadString(doc, "key_id");
        var pem = ReadString(doc, "public_key_pem");
        if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(pem))
        {
            _log.LogError(
                "The management server returned a signing key without a usable " +
                "key_id/public_key_pem pair; nothing was added to the trusted key store.");
            return false;
        }

        var isRevoked = string.Equals(ReadString(doc, "state"), "revoked", StringComparison.OrdinalIgnoreCase);
        if (!TryRegisterKey(keyId!, pem!, isRevoked, ReadString(doc, "revocation_reason")))
        {
            return false;
        }

        _keyStoreHasKeys = true;
        _log.LogInformation("Loaded active signing key '{KeyId}' into the trusted key store.", keyId);
        return true;
    }

    /// <summary>
    /// Validates a published key against its own id and installs it, refusing anything that
    /// contradicts what this agent already trusts.
    /// </summary>
    private bool TryRegisterKey(string keyId, string pem, bool isRevoked, string? revocationReason)
    {
        string fingerprint;
        try
        {
            using var candidate = RSA.Create();
            candidate.ImportFromPem(pem);
            fingerprint = ComputeSpkiFingerprint(candidate);
        }
        catch (Exception ex)
        {
            _log.LogError(
                "Rejected signing key '{KeyId}': its public key PEM could not be parsed ({Message}).",
                keyId, ex.Message);
            return false;
        }

        if (!KeyIdMatchesMaterial(keyId, fingerprint))
        {
            _log.LogError(
                "Rejected signing key '{KeyId}': the server derives this id from the key bytes, " +
                "and these bytes do not hash to that id. Treat the key distribution path as " +
                "tampered with.", keyId);
            return false;
        }

        // GetPublicKey returns null for a revoked id, so a revoked key can never be quietly
        // reinstated through this path either.
        var existing = _keyStore.GetPublicKey(keyId);
        if (existing is not null
            && !string.Equals(ComputeSpkiFingerprint(existing), fingerprint, StringComparison.Ordinal))
        {
            _log.LogError(
                "Refused to replace trusted signing key '{KeyId}': different key material is now " +
                "being published under an id this agent already trusts. Keeping the installed key.",
                keyId);
            return false;
        }

        _keyStore.RegisterPublicKeyPem(keyId, pem, isRevoked);
        if (isRevoked)
        {
            // Re-stated with the server's reason: RegisterPublicKeyPem records only a generic one.
            MarkRevoked(keyId, revocationReason);
        }

        return true;
    }

    private void MarkRevoked(string keyId, string? reason)
    {
        var text = string.IsNullOrWhiteSpace(reason) ? "Revoked by the management server" : reason!;
        _keyStore.RevokeKey(keyId, text);

        try
        {
            _journal.SaveRevokedKey(keyId, text);
        }
        catch (Exception ex)
        {
            _log.LogError(
                "Signing key '{KeyId}' is revoked in memory but the revocation could not be " +
                "persisted ({Message}); it will not survive a restart until the next successful " +
                "keyring fetch.", keyId, ex.Message);
        }
    }

    private static bool KeyIdMatchesMaterial(string keyId, string spkiFingerprintHex)
    {
        if (!keyId.StartsWith(FingerprintKeyIdPrefix, StringComparison.Ordinal))
        {
            // Not a fingerprint-derived id, so there is nothing to cross-check.
            return true;
        }

        var claimed = keyId.Substring(FingerprintKeyIdPrefix.Length);
        if (claimed.Length != FingerprintKeyIdChars)
        {
            return false;
        }

        return spkiFingerprintHex.StartsWith(claimed, StringComparison.OrdinalIgnoreCase);
    }

    private static string ComputeSpkiFingerprint(RSA rsa)
        => Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

    private static string? ReadString(JsonElement obj, string propertyName)
        => obj.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;

    public override void Dispose()
    {
        _keyStoreGate.Dispose();
        base.Dispose();
    }
}
