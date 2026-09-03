using Spemcs.Agent.Core;
using Xunit;
using System.Threading.Channels;

namespace Spemcs.Agent.Tests;

public sealed class ActivationSourceTests
{
    [Fact]
    public async Task Local_activation_source_exposes_backend_replaceable_commands()
    {
        var source = new LocalTestActivationSource();
        await source.PublishStartAsync();
        await source.PublishStopAsync();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var commands = new List<bool>();
        await foreach (var command in source.ReadCommandsAsync(timeout.Token))
        {
            commands.Add(command);
            if (commands.Count == 2) break;
        }

        Assert.Equal([true, false], commands);
    }

    private sealed class LocalTestActivationSource : IExamActivationSource
    {
        private readonly Channel<bool> _channel = Channel.CreateUnbounded<bool>();

        public async Task PublishStartAsync() => await _channel.Writer.WriteAsync(true);
        public async Task PublishStopAsync() => await _channel.Writer.WriteAsync(false);

        public IAsyncEnumerable<bool> ReadCommandsAsync(CancellationToken cancellationToken) => _channel.Reader.ReadAllAsync(cancellationToken);
    }
}
