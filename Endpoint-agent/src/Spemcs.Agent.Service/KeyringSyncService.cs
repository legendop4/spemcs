using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core.Network;

namespace Spemcs.Agent.Service;

public interface IKeyringSyncService
{
    bool HasKeys { get; }
    Task<bool> EnsureKeyStoreInitializedAsync(CancellationToken ct = default);
    Task<bool> EnsureKeyStoreInitializedAsync(string? serverUrl, CancellationToken ct = default);
    Task<bool> ForceRefreshAsync(CancellationToken ct = default);
    Task<bool> ForceRefreshAsync(string? serverUrl, CancellationToken ct = default);
}

public sealed class KeyringSyncService : IKeyringSyncService
{
    private static readonly TimeSpan KeyringRefreshInterval = TimeSpan.FromMinutes(15);

    private readonly ITrustedKeyStore _keyStore;
    private readonly IRollbackJournal _journal;
    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<KeyringSyncService> _log;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private DateTimeOffset _lastKeyringFetchUtc = DateTimeOffset.MinValue;
    private bool _keyStoreHasKeys;
    private bool _revocationsLoadedFromJournal;

    public bool HasKeys => _keyStoreHasKeys || _keyStore.GetActiveKeyIds().Count > 0;

    public KeyringSyncService(
        ITrustedKeyStore keyStore,
        IRollbackJournal journal,
        IHttpClientFactory httpFactory,
        ILogger<KeyringSyncService> log)
    {
        _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _httpFactory = httpFactory ?? throw new ArgumentNullException(nameof(httpFactory));
        _log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public Task<bool> EnsureKeyStoreInitializedAsync(CancellationToken ct = default)
        => RefreshInternalAsync(force: false, serverUrl: null, ct);

    public Task<bool> EnsureKeyStoreInitializedAsync(string? serverUrl, CancellationToken ct = default)
        => RefreshInternalAsync(force: false, serverUrl: serverUrl, ct);

    public Task<bool> ForceRefreshAsync(CancellationToken ct = default)
        => RefreshInternalAsync(force: true, serverUrl: null, ct);

    public Task<bool> ForceRefreshAsync(string? serverUrl, CancellationToken ct = default)
        => RefreshInternalAsync(force: true, serverUrl: serverUrl, ct);

    private async Task<bool> RefreshInternalAsync(bool force, string? serverUrl, CancellationToken ct)
    {
        if (!force && IsKeyringFresh())
        {
            return true;
        }

        try
        {
            await _gate.WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
        }

        try
        {
            if (!force && IsKeyringFresh())
            {
                return true;
            }

            LoadPersistedRevocations();

            var client = _httpFactory.CreateClient("BackendApi");
            if (!string.IsNullOrWhiteSpace(serverUrl))
            {
                client.BaseAddress = new Uri(ServiceConfigResolver.NormalizeUrl(serverUrl));
            }

            var loaded = await TryLoadKeyringAsync(client, ct).ConfigureAwait(false);
            if (!loaded)
            {
                loaded = await TryLoadActiveKeyOnlyAsync(client, ct).ConfigureAwait(false);
            }

            if (loaded)
            {
                _lastKeyringFetchUtc = DateTimeOffset.UtcNow;
                return true;
            }

            if (_keyStoreHasKeys || _keyStore.GetActiveKeyIds().Count > 0)
            {
                _log.LogWarning(
                    "Could not refresh the signing keyring from the management server. Continuing with trusted keys.");
                return true;
            }

            _log.LogError(
                "No policy signing key could be obtained from the management server. Policy verification will fail closed.");
            return false;
        }
        finally
        {
            _gate.Release();
        }
    }

    private bool IsKeyringFresh()
        => (_keyStoreHasKeys || _keyStore.GetActiveKeyIds().Count > 0)
           && (DateTimeOffset.UtcNow - _lastKeyringFetchUtc) < KeyringRefreshInterval;

    private void LoadPersistedRevocations()
    {
        if (_revocationsLoadedFromJournal) return;

        try
        {
            var revoked = _journal.GetRevokedKeys();
            foreach (var keyId in revoked)
            {
                if (string.IsNullOrWhiteSpace(keyId)) continue;
                _keyStore.RevokeKey(keyId, "Revoked before this agent restarted (local journal)");
            }

            _revocationsLoadedFromJournal = true;
        }
        catch (Exception ex)
        {
            _log.LogError("Could not read persisted signing key revocations: {Message}", ex.Message);
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

        var registered = 0;
        foreach (var entry in keysProp.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object) continue;

            var keyId = ReadString(entry, "key_id");
            var pem = ReadString(entry, "public_key_pem");

            if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(pem))
            {
                continue;
            }

            var isRevoked = string.Equals(ReadString(entry, "state"), "revoked", StringComparison.OrdinalIgnoreCase);
            if (TryRegisterKey(keyId!, pem!, isRevoked, ReadString(entry, "revocation_reason")))
            {
                registered++;
            }
        }

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
            "Trusted key store synchronised: {Registered} key(s) registered, {Revoked} revoked, active key '{ActiveKeyId}'.",
            registered, _keyStore.GetRevokedKeyIds().Count, activeId ?? "(unreported)");
        return true;
    }

    private async Task<bool> TryLoadActiveKeyOnlyAsync(HttpClient client, CancellationToken ct)
    {
        JsonElement doc;
        try
        {
            doc = await client
                .GetFromJsonAsync<JsonElement>("api/policies/signing-key/public", ct)
                .ConfigureAwait(false);
        }
        catch
        {
            try
            {
                doc = await client
                    .GetFromJsonAsync<JsonElement>("api/policies/signing-key", ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log.LogWarning("Could not fetch the active signing key fallback: {Message}", ex.Message);
                return false;
            }
        }

        if (doc.ValueKind != JsonValueKind.Object) return false;

        var keyId = ReadString(doc, "key_id");
        var pem = ReadString(doc, "public_key_pem");

        if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(pem))
        {
            _log.LogWarning("The active signing key fallback response was missing key_id or public_key_pem.");
            return false;
        }

        var isRevoked = string.Equals(ReadString(doc, "state"), "revoked", StringComparison.OrdinalIgnoreCase);
        if (!TryRegisterKey(keyId!, pem!, isRevoked, ReadString(doc, "revocation_reason")))
        {
            return false;
        }

        _keyStoreHasKeys = true;
        _log.LogInformation("Loaded active signing key '{KeyId}' via fallback endpoint.", keyId);
        return true;
    }

    private bool TryRegisterKey(string keyId, string pem, bool isRevoked, string? revocationReason)
    {
        try
        {
            _keyStore.RegisterPublicKeyPem(keyId, pem, isRevoked);
            if (isRevoked)
            {
                MarkRevoked(keyId, revocationReason);
            }
            return true;
        }
        catch (Exception ex)
        {
            _log.LogError("Could not register key '{KeyId}': {Message}", keyId, ex.Message);
            return false;
        }
    }

    private void MarkRevoked(string keyId, string? reason)
    {
        try
        {
            _keyStore.RevokeKey(keyId, reason ?? "");
            _journal.SaveRevokedKey(keyId, reason ?? "Revoked by management server");
        }
        catch (Exception ex)
        {
            _log.LogWarning("Could not mark key '{KeyId}' as revoked: {Message}", keyId, ex.Message);
        }
    }

    private static string? ReadString(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out var prop)
            && prop.ValueKind == JsonValueKind.String)
        {
            return prop.GetString();
        }
        return null;
    }
}
