using System;
using System.Net.Http;
using System.Net.Http.Json;
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
    private readonly ILogger<ControlPipeWorker> _log;
    private readonly AgentWorker _agent;
    private readonly IEnforcementStateMachine _enforcement;
    private readonly ITrustedKeyStore _keyStore;
    private readonly IRollbackJournal _journal;
    private readonly IHttpClientFactory _httpFactory;

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

        // Pre-fetch signing key on startup
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

                        var actResult = await _enforcement.ActivateAsync(
                            p.SessionId,
                            signedMsg,
                            p.ExamId,
                            (FirewallProfiles)p.TargetProfiles,
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

    private async Task EnsureKeyStoreInitializedAsync(CancellationToken ct)
    {
        try
        {
            var client = _httpFactory.CreateClient("BackendApi");
            var keyResp = await client.GetFromJsonAsync<JsonElement>("api/policies/signing-key/public", ct);
            if (keyResp.TryGetProperty("public_key_pem", out var pemProp))
            {
                var pem = pemProp.GetString();
                var keyId = keyResp.TryGetProperty("key_id", out var kProp) ? kProp.GetString() ?? "dev-key-1" : "dev-key-1";
                if (!string.IsNullOrEmpty(pem))
                {
                    _keyStore.RegisterPublicKeyPem(keyId, pem);
                    _log.LogInformation("Loaded signing key '{KeyId}' into TrustedKeyStore.", keyId);
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning("Could not fetch public key from central server: {Message}", ex.Message);
        }
    }
}
