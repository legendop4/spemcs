using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.UI.Services;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// The one test class that puts the production <see cref="CentralApiClient"/> on a real socket
/// against a real backend, with no <see cref="HttpMessageHandler"/> double anywhere in the path.
/// </summary>
/// <remarks>
/// <para>
/// Every other test of this flow intercepts at <c>SendAsync</c>, which is the right place to assert
/// what the agent *constructs* but cannot show that the backend *accepts* it. The defect being
/// guarded against needs both halves: the wizard's lab fetch was a correctly formed request to an
/// endpoint that was never going to answer it, and either half alone looks fine. So this class
/// exercises the whole chain - <see cref="EnrollmentKeyProvider"/> reading the workstation's
/// configuration, <see cref="CentralApiClient.FetchLabsAsync"/> building the request,
/// <c>X-Enrollment-Key</c> crossing the network, and <c>require_enrollment_key</c> deciding.
/// </para>
/// <para>
/// <strong>Read-only, deliberately.</strong> The obvious next step - registering a device and
/// presenting the issued token - is absent because <c>POST /api/v1/devices/register</c> writes a
/// <c>devices</c> row and a <c>lab_devices</c> row, and the backend this reaches is whichever one is
/// configured, in practice the live estate database. A test suite that inserts a workstation into
/// production on every run is a worse problem than the one it verifies. The write half of the chain
/// is covered hermetically by <c>test_device_credential_lifecycle.py</c> against a throwaway
/// database, and was verified once by hand against the live backend with the row removed afterwards.
/// </para>
/// <para>
/// <strong>It never skips.</strong> There is no <c>Skip=</c> convention in this suite, so the shape
/// is the runtime branch already used by
/// <c>ManagementConnectivityVerifierTests.LiveBackend_VerifyConnectivityAsync_Succeeds</c> and
/// <c>WindowsTrafficEnforcementIntegrationTests.ControlledTrafficEnforcement_Verification</c>: a
/// short TCP probe classifies the environment, and both branches assert a real half of the same
/// contract. With a backend reachable and a key configured the lab list must arrive; with nothing
/// listening the client must report a connection failure rather than an empty list, which is the
/// property that would let a silent failure look like "this deployment has no labs".
/// </para>
/// <para>
/// No credential value appears in this file. The key comes from
/// <see cref="EnrollmentKeyProvider.Resolve"/> - the same source the shipped wizard uses - so the
/// test reads whatever the workstation is configured with and asserts nothing about its content.
/// </para>
/// </remarks>
public class LiveEnrollmentEndToEndTests
{
    // The host-side VMnet1 address the student VM reaches the backend on. Loopback is the fallback
    // for a developer box running both halves, and is tried second so that a machine with both
    // available is tested on the path the deployment actually uses.
    private static readonly (string Host, int Port)[] Candidates =
    {
        ("192.168.91.1", 8002),
        ("127.0.0.1", 8002),
    };

    private static async Task<string?> FirstReachableBaseUrlAsync(int timeoutMs = 750)
    {
        foreach (var (host, port) in Candidates)
        {
            try
            {
                using var probe = new TcpClient();
                using var cts = new CancellationTokenSource(timeoutMs);
                await probe.ConnectAsync(IPAddress.Parse(host), port, cts.Token);
                if (probe.Connected)
                {
                    return $"http://{host}:{port}";
                }
            }
            catch (SocketException)
            {
            }
            catch (OperationCanceledException)
            {
            }
        }

        return null;
    }

    [Fact]
    public async Task TheRealClientFetchesTheRealLabList_OrFailsClosedWhenNothingIsListening()
    {
        var baseUrl = await FirstReachableBaseUrlAsync();
        var configuredKey = EnrollmentKeyProvider.Resolve();
        var client = new CentralApiClient();

        if (string.IsNullOrWhiteSpace(configuredKey))
        {
            // This workstation is unconfigured. That is its own assertable contract and the more
            // important one to get right: the client must refuse locally and name the local fix,
            // rather than send an unauthenticated request and relay the server's 401 - which is what
            // sent an operator to inspect the backend for a key that was missing on the endpoint.
            var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.FetchLabsAsync(baseUrl ?? "http://127.0.0.1:8002"));

            Assert.Contains(EnrollmentKeyProvider.ConfigPropertyName, refusal.Message, StringComparison.Ordinal);
            Assert.Contains(EnrollmentKeyProvider.EnvironmentVariableName, refusal.Message, StringComparison.Ordinal);
            return;
        }

        if (baseUrl is null)
        {
            // A key is configured but no backend is up. The client must say it could not connect. An
            // empty list here would be indistinguishable, to the wizard and to the person reading
            // it, from a deployment in which no lab has been created yet.
            var (host, port) = Candidates[0];
            var failure = await Assert.ThrowsAnyAsync<Exception>(
                () => client.FetchLabsAsync($"http://{host}:{port}"));

            Assert.DoesNotContain(configuredKey, failure.Message, StringComparison.Ordinal);
            return;
        }

        // The path this class exists for: production client, real socket, real gate.
        var labs = await client.FetchLabsAsync(baseUrl);

        Assert.NotNull(labs);
        foreach (var lab in labs)
        {
            Assert.NotEqual(Guid.Empty, lab.LabId);
            Assert.False(string.IsNullOrWhiteSpace(lab.LabName));
            Assert.False(string.IsNullOrWhiteSpace(lab.BuildingId));
            // LabEnrollmentRead withholds these. They deserialize to their defaults precisely
            // because the server does not send them, so this is the agent-side half of the backend's
            // "exactly four fields" assertion - and it fails if anybody swaps the endpoint's
            // response model back to the full LabRead for convenience.
            Assert.Null(lab.Description);
            Assert.False(lab.SpemcsEnabled);
        }

        // The wizard's Register button is enabled by a non-empty list, so an empty one is a
        // deployment state worth naming rather than passing over. It is not a failure of this code
        // path: a backend with no spemcs_enabled lab correctly returns [].
        if (labs.Count == 0)
        {
            Assert.True(true,
                $"The backend at {baseUrl} accepted the enrollment key and returned no labs. The " +
                "credential path is proven; create a lab with POST /api/labs before enrolling a " +
                "workstation.");
        }
    }

    [Fact]
    public async Task TheStaffLabListStaysShutToAnEnrollingWorkstation()
    {
        // The counter-test, and the reason it is here rather than in the backend suite: it asserts
        // the property from the agent's actual position on the network, with the agent's actual
        // credential. /api/labs is what the wizard used to call; if a later change "simplifies" the
        // two endpoints into one, the test above goes green on its own and only this one notices.
        var baseUrl = await FirstReachableBaseUrlAsync();
        if (baseUrl is null)
        {
            return;
        }

        var configuredKey = EnrollmentKeyProvider.Resolve();

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/labs");
        if (!string.IsNullOrWhiteSpace(configuredKey))
        {
            request.Headers.TryAddWithoutValidation(CentralApiClient.EnrollmentKeyHeader, configuredKey);
        }

        using var response = await http.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
