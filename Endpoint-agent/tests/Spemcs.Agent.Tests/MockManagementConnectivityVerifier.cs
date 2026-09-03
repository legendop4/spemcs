using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;

namespace Spemcs.Agent.Tests;

public sealed class MockManagementConnectivityVerifier : IManagementConnectivityVerifier
{
    public bool ShouldSucceed { get; set; }
    public int CallCount { get; private set; }
    public ManagementDestination? LastDestination { get; private set; }

    public MockManagementConnectivityVerifier(bool shouldSucceed = true)
    {
        ShouldSucceed = shouldSucceed;
    }

    public Task<bool> VerifyConnectivityAsync(ManagementDestination destination, CancellationToken cancellationToken = default)
    {
        CallCount++;
        LastDestination = destination;
        return Task.FromResult(ShouldSucceed);
    }
}
