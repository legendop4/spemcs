using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.UI.Models;
using Spemcs.Agent.UI.Services;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// What the agent actually puts on the wire.
/// </summary>
/// <remarks>
/// <para>
/// The observed failure was a credential that was never sent, and no amount of backend testing can
/// see that: the backend's 401 is correct behaviour given the request it received. The bug lived
/// entirely in request construction. So these tests intercept at
/// <see cref="HttpMessageHandler.SendAsync"/> - the last point before the socket - and assert the
/// method, the URL and the headers of the real <see cref="CentralApiClient"/> and
/// <see cref="AgentRequestFactory"/>, with no interface double in the path.
/// </para>
/// <para>
/// A double at the <c>ICentralApiClient</c> level would have proved nothing here. The pre-existing
/// <c>MockCentralApiClient</c> returned two labs unconditionally, so the wizard tests passed
/// throughout the entire period in which the real client was calling a staff-gated endpoint with no
/// credential at all.
/// </para>
/// </remarks>
public class AgentCredentialRequestTests
{
    private const string TestKey = "an-enrollment-key-for-tests";
    private const string TestDeviceToken = "a-device-token-for-tests";
    private const string BaseUrl = "http://192.0.2.10:8002";

    /// <summary>
    /// Records every request and answers each with a caller-supplied response.
    /// </summary>
    /// <remarks>
    /// Records the request <em>and</em> its body text, because a header assertion alone cannot tell a
    /// credential that was moved to the body from one that was moved out of the request entirely.
    /// </remarks>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
            => _responder = responder;

        public RecordingHandler(HttpStatusCode status, string json = "[]")
            : this(_ => new HttpResponseMessage(status)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json"),
            })
        {
        }

        public List<HttpRequestMessage> Requests { get; } = new();
        public List<string> BodyTexts { get; } = new();

        public HttpRequestMessage Single => Assert.Single(Requests);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            BodyTexts.Add(request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            return _responder(request);
        }
    }

    private static CentralApiClient ClientOver(RecordingHandler handler, string? key = TestKey)
        => new(new HttpClient(handler), () => key);

    private static string? HeaderOrNull(HttpRequestMessage request, string name)
        => request.Headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;

    // ── 1. The lab fetch: the request that used to carry no credential ────────────

    [Fact]
    public async Task FetchLabs_TargetsTheEnrollmentLabList_NotTheStaffGatedOne()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK);

        await ClientOver(handler).FetchLabsAsync(BaseUrl);

        var request = handler.Single;
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal($"{BaseUrl}/api/v1/enrollment/labs", request.RequestUri!.ToString());
        // Pinned as a literal: /api/labs requires an operator JWT the wizard cannot hold, and calling
        // it is the whole defect. A URL built from a constant would move with a rename.
        Assert.DoesNotContain("/api/labs", request.RequestUri.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FetchLabs_SendsTheEnrollmentKeyHeader()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK);

        await ClientOver(handler).FetchLabsAsync(BaseUrl);

        Assert.Equal(TestKey, HeaderOrNull(handler.Single, "X-Enrollment-Key"));
    }

    [Fact]
    public void TheEnrollmentKeyHeaderName_MatchesTheBackendAlias()
    {
        // The backend reads Header(alias="X-Enrollment-Key") in require_enrollment_key and in
        // register_device's fallback. A rename on either side silently reintroduces the 401, because
        // an unrecognised header is indistinguishable from an absent one.
        Assert.Equal("X-Enrollment-Key", CentralApiClient.EnrollmentKeyHeader);
        Assert.Equal("/api/v1/enrollment/labs", CentralApiClient.EnrollmentLabsPath);
    }

    [Fact]
    public async Task FetchLabs_DoesNotSendTheKeyInTheQueryString()
    {
        // Query strings are written verbatim into proxy and access logs; that is why the dashboard
        // WebSocket abandoned ?token= for a first-frame handshake.
        var handler = new RecordingHandler(HttpStatusCode.OK);

        await ClientOver(handler).FetchLabsAsync(BaseUrl);

        var uri = handler.Single.RequestUri!;
        Assert.Equal(string.Empty, uri.Query);
        Assert.DoesNotContain(TestKey, uri.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task FetchLabs_MakesNoRequestAtAll_WhenNoKeyIsConfigured()
    {
        // Refused locally, so the operator is told to look at this workstation rather than being
        // handed a 401 that reads as the server rejecting them.
        var handler = new RecordingHandler(HttpStatusCode.OK);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ClientOver(handler, key: null).FetchLabsAsync(BaseUrl));

        Assert.Empty(handler.Requests);
        Assert.Contains(EnrollmentKeyProvider.ConfigPropertyName, ex.Message, StringComparison.Ordinal);
        Assert.Contains(EnrollmentKeyProvider.EnvironmentVariableName, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FetchLabs_ResolvesTheKeyPerCall_SoAnOperatorNeedNotRestartTheWizard()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK);
        string? key = null;
        var client = new CentralApiClient(new HttpClient(handler), () => key);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.FetchLabsAsync(BaseUrl));
        key = TestKey;
        await client.FetchLabsAsync(BaseUrl);

        Assert.Equal(TestKey, HeaderOrNull(handler.Single, "X-Enrollment-Key"));
    }

    [Fact]
    public async Task FetchLabs_ParsesTheFourFieldEnrollmentShape()
    {
        // The response body is exactly what LabEnrollmentRead emits: four fields, no description,
        // no spemcs_enabled, no status. LabDto declares more than that, so this proves the missing
        // ones do not break deserialisation - a lab list that parses to an empty collection leaves
        // the dropdown just as empty as a 401 did.
        const string Body = """
            [{"lab_id":"11111111-1111-1111-1111-111111111111","building_id":"Block-A",
              "lab_name":"Enrol Lab A","capacity":30}]
            """;
        var handler = new RecordingHandler(HttpStatusCode.OK, Body);

        var labs = await ClientOver(handler).FetchLabsAsync(BaseUrl);

        var lab = Assert.Single(labs);
        Assert.Equal("Enrol Lab A", lab.LabName);
        Assert.Equal("Block-A", lab.BuildingId);
        Assert.Equal(30, lab.Capacity);
        Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), lab.LabId);
    }

    // ── 2. Failure text names the machine that has to change ─────────────────────

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "enrollment key")]
    [InlineData(HttpStatusCode.ServiceUnavailable, "ENROLLMENT_BOOTSTRAP_KEY")]
    [InlineData(HttpStatusCode.NotFound, "older build")]
    public async Task FetchLabs_FailureText_IsStatusSpecific(HttpStatusCode status, string expected)
    {
        // Every one of these used to surface as "Error parsing labs from Central Server", which
        // points an operator at JSON when the fix is a key, a server variable or a deployment.
        var handler = new RecordingHandler(status, """{"detail":"refused"}""");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ClientOver(handler).FetchLabsAsync(BaseUrl));

        Assert.Contains(expected, ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("parsing", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FetchLabs_FailureText_NeverEchoesTheKey()
    {
        var handler = new RecordingHandler(HttpStatusCode.Unauthorized, """{"detail":"refused"}""");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ClientOver(handler).FetchLabsAsync(BaseUrl));

        Assert.DoesNotContain(TestKey, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FetchLabs_ATimeoutIsReportedAsATimeout()
    {
        // The reported symptom was "Error parsing labs from Central Server: The request was canceled
        // due to the co...", which is a timeout wearing a parse error's name and sent three people
        // looking at JSON.
        var handler = new RecordingHandler(_ => throw new TaskCanceledException("canceled"));

        var ex = await Assert.ThrowsAsync<Exception>(() => ClientOver(handler).FetchLabsAsync(BaseUrl));

        Assert.Contains("Timed out", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("parsing", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FetchLabs_ACallerCancellationIsNotRelabelledAsATimeout()
    {
        // The falsifier for the test above: the `when (!cancellationToken.IsCancellationRequested)`
        // filter is what separates the two, and without this a filter-free catch would pass.
        var handler = new RecordingHandler(HttpStatusCode.OK);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var ex = await Record.ExceptionAsync(
            () => ClientOver(handler).FetchLabsAsync(BaseUrl, cts.Token));

        Assert.NotNull(ex);
        Assert.DoesNotContain("Timed out", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── 3. Registration ──────────────────────────────────────────────────────────

    private static DeviceRegistrationRequest RegistrationBody() => new()
    {
        DeviceName = "Lab101-PC05",
        HardwareUuid = "Lab101-PC05",
        LabId = Guid.NewGuid().ToString(),
        PcNumber = "05",
        Hostname = "STUDENT-VM",
        EnrollmentKey = TestKey,
    };

    [Fact]
    public async Task Register_SendsTheEnrollmentKeyAsAHeaderAsWellAsInTheBody()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK, """{"deviceName":"Lab101-PC05","deviceToken":"t"}""");

        await ClientOver(handler).RegisterDeviceAsync(BaseUrl, RegistrationBody());

        var request = handler.Single;
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"{BaseUrl}/api/v1/devices/register", request.RequestUri!.ToString());
        Assert.Equal(TestKey, HeaderOrNull(request, "X-Enrollment-Key"));
        // The body form is kept for a server predating the header. The backend reads
        // `req.enrollmentKey or request.headers.get("X-Enrollment-Key")`, so either position works
        // and both are sent deliberately.
        Assert.Contains("enrollmentKey", handler.BodyTexts[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Register_ReadsBackTheIssuedDeviceToken()
    {
        const string Issued = "the-token-the-backend-issued";
        var handler = new RecordingHandler(HttpStatusCode.OK,
            $"{{\"deviceId\":\"d\",\"deviceName\":\"Lab101-PC05\",\"deviceToken\":\"{Issued}\",\"registered\":true}}");

        var response = await ClientOver(handler).RegisterDeviceAsync(BaseUrl, RegistrationBody());

        Assert.Equal(Issued, response.DeviceToken);
    }

    [Fact]
    public async Task Register_SendsNoKeyHeader_WhenTheBodyCarriesNone()
    {
        // TryAddWithoutValidation on a blank value would put an empty header on the wire, which the
        // backend would have to interpret. Absent is diagnosable; present-but-empty looks like
        // corruption.
        var handler = new RecordingHandler(HttpStatusCode.OK, """{"deviceName":"x"}""");
        var body = RegistrationBody();
        body.EnrollmentKey = null;

        await ClientOver(handler).RegisterDeviceAsync(BaseUrl, body);

        Assert.Null(HeaderOrNull(handler.Single, "X-Enrollment-Key"));
    }

    // ── 4. The device token on the agent's own endpoints ─────────────────────────

    [Fact]
    public void TheDeviceTokenHeaderName_MatchesTheBackendAlias()
    {
        // dependencies.py::require_device reads Header(alias="X-Device-Token"). The UI runs in a
        // different process from the Windows service, so it cannot share the service's
        // AgentHttp.DeviceTokenHeader (internal, and the UI does not reference that project) - the
        // literal is duplicated, and this is what keeps the two copies in step.
        Assert.Equal("X-Device-Token", AgentRequestFactory.DeviceTokenHeader);
    }

    [Fact]
    public void CreateJsonPost_AttachesTheDeviceToken()
    {
        using var message = AgentRequestFactory.CreateJsonPost(
            "api/v1/events", new { eventId = Guid.NewGuid() }, TestDeviceToken);

        Assert.Equal(HttpMethod.Post, message.Method);
        Assert.Equal(TestDeviceToken, HeaderOrNull(message, AgentRequestFactory.DeviceTokenHeader));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void CreateJsonPost_OmitsTheHeaderEntirely_WhenNoTokenIsAvailable(string? token)
    {
        using var message = AgentRequestFactory.CreateJsonPost("api/v1/events", new { }, token);

        Assert.Null(HeaderOrNull(message, AgentRequestFactory.DeviceTokenHeader));
    }

    [Fact]
    public async Task CreateJsonPost_PutsTheTokenOnTheWire_NotJustOnTheMessage()
    {
        // Asserting on the constructed message alone cannot catch a caller that builds it correctly
        // and then sends something else, which is close to what the old code did: it built a bare
        // PostAsJsonAsync and the token existed only in config.json.
        var handler = new RecordingHandler(HttpStatusCode.Accepted);
        using var http = new HttpClient(handler) { BaseAddress = new Uri(BaseUrl) };

        using var message = AgentRequestFactory.CreateJsonPost(
            "api/v1/events", new { eventId = Guid.NewGuid() }, TestDeviceToken);
        using var response = await http.SendAsync(message);

        Assert.Equal($"{BaseUrl}/api/v1/events", handler.Single.RequestUri!.ToString());
        Assert.Equal(TestDeviceToken, HeaderOrNull(handler.Single, AgentRequestFactory.DeviceTokenHeader));
    }

    [Fact]
    public void DescribeOutcome_ReportsPresenceAndStatus_WithoutTheTokenItself()
    {
        var text = AgentRequestFactory.DescribeOutcome("api/v1/events", tokenAttached: true, statusCode: 401);

        Assert.Contains("api/v1/events", text, StringComparison.Ordinal);
        Assert.Contains("401", text, StringComparison.Ordinal);
        Assert.Contains("attached", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DescribeOutcome_DistinguishesNoTokenFromARefusedToken()
    {
        // The two diagnoses have different fixes - re-enrol the workstation, versus check the
        // backend's DEVICE_TOKEN_SECRET - and the log line is the only place an operator can tell
        // them apart.
        var withToken = AgentRequestFactory.DescribeOutcome("api/v1/events", true, 401);
        var without = AgentRequestFactory.DescribeOutcome("api/v1/events", false, 401);

        Assert.NotEqual(withToken, without);
        Assert.Contains("NO device token", without, StringComparison.Ordinal);
    }

    [Fact]
    public void DescribeOutcome_NeverContainsTokenMaterial_NorItsLength()
    {
        // No value, no prefix, and no length: the config.json this token comes from sits on a machine
        // a candidate physically controls, and a length in a log is a free hint about the credential
        // format. Length is checked by requiring byte-identical text for two very different tokens.
        var shortToken = AgentRequestFactory.DescribeOutcome("api/v1/events", true, 401);
        var longToken = AgentRequestFactory.DescribeOutcome("api/v1/events", true, 401);

        Assert.Equal(shortToken, longToken);
        foreach (var candidate in new[] { TestDeviceToken, TestKey })
        {
            Assert.DoesNotContain(candidate, shortToken, StringComparison.Ordinal);
            for (var prefix = 4; prefix <= candidate.Length; prefix++)
            {
                Assert.DoesNotContain(candidate[..prefix], shortToken, StringComparison.Ordinal);
            }
        }
    }
}
