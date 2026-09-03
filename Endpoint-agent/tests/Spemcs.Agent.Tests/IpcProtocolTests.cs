using Spemcs.Agent.Ipc;
using System.Text;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class IpcProtocolTests
{
    [Fact]
    public void Named_pipe_server_is_created_with_supported_acl_path()
    {
        using var server = PipeProtocol.CreateServer($"spemcs-test-{Guid.NewGuid():N}");
        Assert.False(server.IsConnected);
    }

    [Fact]
    public async Task Malformed_payload_is_rejected_without_throwing()
    {
        await using var stream = new MemoryStream(Encoding.UTF8.GetBytes("not-json\n"));
        Assert.Null(await PipeProtocol.ReadAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Envelope_round_trips_type_version_and_payload()
    {
        await using var stream = new MemoryStream(); await PipeProtocol.WriteAsync(stream, MessageTypes.RegistrationData, new RegistrationPayload("LAB-1", "127.0.0.1"), CancellationToken.None);
        stream.Position = 0; var envelope = await PipeProtocol.ReadAsync(stream, CancellationToken.None);
        Assert.NotNull(envelope); Assert.Equal(MessageTypes.RegistrationData, envelope!.Type); Assert.Equal(1, envelope.Version); Assert.Equal("LAB-1", envelope.Payload.GetProperty("DeviceName").GetString());
    }
}
