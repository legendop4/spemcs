using Spemcs.Agent.Ipc;

namespace Spemcs.Agent.TestHarness;

public sealed class ServiceControlClient
{
    public async Task<bool> SendAsync(string command, CancellationToken cancellationToken)
    {
        await using var pipe = PipeProtocol.CreateClient(PipeNames.Control);
        await pipe.ConnectAsync(5000, cancellationToken);
        await PipeProtocol.WriteAsync(pipe, command, new { }, cancellationToken);
        var response = await PipeProtocol.ReadAsync(pipe, cancellationToken);
        return response?.Payload.TryGetProperty("Accepted", out var accepted) == true && accepted.GetBoolean();
    }
}
