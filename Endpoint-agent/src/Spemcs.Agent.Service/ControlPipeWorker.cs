using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Ipc;

namespace Spemcs.Agent.Service;

public sealed class ControlPipeWorker : BackgroundService
{
    private readonly ILogger<ControlPipeWorker> _log;
    private readonly AgentWorker _agent;

    public ControlPipeWorker(ILogger<ControlPipeWorker> log, AgentWorker agent)
    {
        _log = log;
        _agent = agent;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        _log.LogInformation("Control pipe worker started, listening on {PipeName}", PipeNames.Control);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = PipeProtocol.CreateServer(PipeNames.Control);
                await pipe.WaitForConnectionAsync(stoppingToken);
                var request = await PipeProtocol.ReadAsync(pipe, stoppingToken);
                if (request is null) continue;

                _log.LogInformation("Received control pipe request: {Type}", request.Type);
                var accepted = request.Type switch
                {
                    MessageTypes.StartExam => await _agent.StartExamAsync(stoppingToken),
                    MessageTypes.StopExam => await _agent.StopExamAsync(stoppingToken),
                    _ => false
                };

                await PipeProtocol.WriteAsync(pipe, MessageTypes.CommandResult, new CommandResultPayload(accepted, "handled"), stoppingToken);
                _log.LogInformation("Replied to control request {Type} with accepted={Accepted}", request.Type, accepted);
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
}
