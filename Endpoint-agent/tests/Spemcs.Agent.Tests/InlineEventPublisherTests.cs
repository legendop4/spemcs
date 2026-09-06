using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core;
using Spemcs.Agent.UI;
using Spemcs.Agent.UI.Services;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// The violation-reporting path in the UI process, which is where the observed
/// <c>POST /api/v1/events -&gt; 401 Unauthorized</c> stream came from.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="InlineEventPublisher"/> is the real production class here - not a double - driven over
/// a recording <see cref="HttpMessageHandler"/>. That matters because the defect was not in a
/// decision this class makes but in the request it builds: it posted through a bare
/// <see cref="HttpClient"/> with no <c>X-Device-Token</c> and swallowed the refusal in an empty
/// catch, so every detected violation was rejected and nothing said so.
/// </para>
/// <para>
/// The token is read through a delegate on every call rather than captured once, because the
/// WebSocket self-heal path can write a freshly issued token into the config while monitoring is
/// already running. <see cref="ReadsTheTokenPerEvent_SoASelfHealedTokenTakesEffectMidSession"/> is
/// the test that stops that from being reverted to a captured string.
/// </para>
/// </remarks>
public class InlineEventPublisherTests
{
    private const string TestDeviceToken = "a-device-token-for-tests";

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public RecordingHandler(HttpStatusCode status = HttpStatusCode.OK)
            : this(_ => new HttpResponseMessage(status)
            {
                Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json"),
            })
        {
        }

        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
            => _responder = responder;

        public List<HttpRequestMessage> Requests { get; } = new();
        public List<string> BodyTexts { get; } = new();
        public List<string?> TokenHeaders { get; } = new();

        public HttpRequestMessage Single => Assert.Single(Requests);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            TokenHeaders.Add(
                request.Headers.TryGetValues(AgentRequestFactory.DeviceTokenHeader, out var values)
                    ? values.FirstOrDefault()
                    : null);
            BodyTexts.Add(request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            return _responder(request);
        }
    }

    private static ViolationEvent Violation() => new(
        EventId: Guid.NewGuid(),
        DeviceName: "Lab101-PC05",
        StudentRollNumber: "2301921540174",
        EventType: "BLOCKED_PROCESS",
        ProcessId: 8080,
        ProcessName: "anydesk.exe",
        TimestampUtc: DateTimeOffset.UtcNow,
        ExecutablePath: @"C:\Program Files\AnyDesk\AnyDesk.exe",
        Reason: "Prohibited remote access tool");

    private static (InlineEventPublisher Publisher, RecordingHandler Handler) PublisherOver(
        RecordingHandler handler, Func<string?> token)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("http://192.0.2.10:8002") };
        return (new InlineEventPublisher(http, token), handler);
    }

    // ── 1. The credential reaches the wire ────────────────────────────────────────

    [Fact]
    public async Task PostsTheEventWithTheDeviceTokenHeader()
    {
        var (publisher, handler) = PublisherOver(new RecordingHandler(), () => TestDeviceToken);

        await publisher.PublishEventAsync(Violation());

        var request = handler.Single;
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("http://192.0.2.10:8002/api/v1/events", request.RequestUri!.ToString());
        Assert.Equal(TestDeviceToken, handler.TokenHeaders[0]);
    }

    [Fact]
    public async Task TheEventBodyCarriesTheFieldsTheBackendSchemaRequires()
    {
        // A credential that arrives on a body the backend rejects with 422 is no better than no
        // credential. The names are camelCase because that is what EventCreateReq declares.
        var (publisher, handler) = PublisherOver(new RecordingHandler(), () => TestDeviceToken);
        var violation = Violation();

        await publisher.PublishEventAsync(violation);

        var body = handler.BodyTexts[0];
        foreach (var field in new[]
                 { "eventId", "deviceName", "eventType", "processId", "processName", "timestampUtc" })
        {
            Assert.Contains($"\"{field}\"", body, StringComparison.Ordinal);
        }
        Assert.Contains(violation.EventId.ToString(), body, StringComparison.Ordinal);
        Assert.Contains("anydesk.exe", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheTokenIsNeverPlacedInTheBodyOrTheQueryString()
    {
        // require_device reads a header. A token in the body would be ignored by the backend, and a
        // token in the query string would be written verbatim into every proxy and access log.
        var (publisher, handler) = PublisherOver(new RecordingHandler(), () => TestDeviceToken);

        await publisher.PublishEventAsync(Violation());

        Assert.DoesNotContain(TestDeviceToken, handler.BodyTexts[0], StringComparison.Ordinal);
        Assert.Equal(string.Empty, handler.Single.RequestUri!.Query);
    }

    [Fact]
    public async Task ReadsTheTokenPerEvent_SoASelfHealedTokenTakesEffectMidSession()
    {
        // The falsifier for a captured-by-value token. Monitoring starts before the WebSocket
        // self-heal registration can complete, so the first events legitimately go out with no
        // credential; every event after the token arrives must carry it. A captured null would leave
        // the whole rest of the exam unauthenticated.
        string? token = null;
        var (publisher, handler) = PublisherOver(new RecordingHandler(), () => token);

        await publisher.PublishEventAsync(Violation());
        token = TestDeviceToken;
        await publisher.PublishEventAsync(Violation());

        Assert.Equal(2, handler.Requests.Count);
        Assert.Null(handler.TokenHeaders[0]);
        Assert.Equal(TestDeviceToken, handler.TokenHeaders[1]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task OmitsTheHeaderEntirely_RatherThanSendingABlankOne(string? token)
    {
        // Absent is diagnosable; present-but-empty looks like corruption and forces the backend to
        // interpret it.
        var (publisher, handler) = PublisherOver(new RecordingHandler(), () => token);

        await publisher.PublishEventAsync(Violation());

        Assert.Null(handler.TokenHeaders[0]);
    }

    [Fact]
    public async Task TheEventIsStillPostedWhenNoTokenIsAvailable()
    {
        // Deliberately NOT refused locally, unlike registration. A 401 recorded on the server and in
        // the local log is more useful than a violation that was never reported at all, and this path
        // runs during a live exam where the token may still be arriving.
        var (publisher, handler) = PublisherOver(new RecordingHandler(), () => null);

        await publisher.PublishEventAsync(Violation());

        Assert.Single(handler.Requests);
    }

    // ── 2. A refusal is recorded, not swallowed ───────────────────────────────────

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.BadRequest)]
    public void ARefusalProducesALogLineNamingTheEndpointAndTheStatus(HttpStatusCode status)
    {
        // Asserted through the same DescribeOutcome the publisher calls, because LogUi writes to
        // %ProgramData% and a test must not depend on - or pollute - that file. What is being pinned
        // is that the text an operator reads identifies the endpoint, the status, and whether a
        // credential was attached, which are the three facts that separate "re-enrol this
        // workstation" from "check the backend's DEVICE_TOKEN_SECRET".
        var text = AgentRequestFactory.DescribeOutcome("api/v1/events", true, (int)status);

        Assert.Contains("api/v1/events", text, StringComparison.Ordinal);
        Assert.Contains(((int)status).ToString(), text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASuccessfulPostDoesNotThrow()
    {
        // A monitored session emits an event per process transition, so this path runs continuously.
        var (publisher, _) = PublisherOver(new RecordingHandler(HttpStatusCode.OK), () => TestDeviceToken);

        await publisher.PublishEventAsync(Violation());
    }

    [Fact]
    public async Task ATransportFailureIsNonFatal_SoMonitoringSurvivesABackendOutage()
    {
        // The backend going away mid-exam must not take the agent's process monitor down with it.
        var handler = new RecordingHandler(_ => throw new HttpRequestException("connection refused"));
        var (publisher, _) = PublisherOver(handler, () => TestDeviceToken);

        await publisher.PublishEventAsync(Violation());
    }

    [Fact]
    public async Task ACancellationIsNonFatalToo()
    {
        var handler = new RecordingHandler(_ => throw new TaskCanceledException("canceled"));
        var (publisher, _) = PublisherOver(handler, () => TestDeviceToken);

        await publisher.PublishEventAsync(Violation());
    }

    [Fact]
    public async Task AnUnexpectedExceptionIsNotSwallowed()
    {
        // The falsifier for the two tests above: they prove HttpRequestException and
        // TaskCanceledException are tolerated, and would pass just as happily against a blanket
        // `catch { }` - which is exactly the code that hid the 401s. The `when` filter is what
        // separates "expected transport failure" from "a bug in this method", and only an
        // unfiltered catch would let this one through.
        var handler = new RecordingHandler(_ => throw new InvalidOperationException("a real bug"));
        var (publisher, _) = PublisherOver(handler, () => TestDeviceToken);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => publisher.PublishEventAsync(Violation()));
    }

    // ── 3. Nothing credential-shaped is written to the log ────────────────────────

    [Fact]
    public void TheLogTextForAnyStatusNeverContainsTheToken()
    {
        // Walked over every status the backend can answer with, because the leak that matters is one
        // that appears on exactly the code path an operator is most likely to be reading.
        foreach (var status in new[] { 200, 400, 401, 403, 404, 422, 500, 503 })
        {
            foreach (var attached in new[] { true, false })
            {
                var text = AgentRequestFactory.DescribeOutcome("api/v1/events", attached, status);
                Assert.DoesNotContain(TestDeviceToken, text, StringComparison.Ordinal);
                for (var prefix = 4; prefix <= TestDeviceToken.Length; prefix++)
                {
                    Assert.DoesNotContain(TestDeviceToken[..prefix], text, StringComparison.Ordinal);
                }
            }
        }
    }

    [Fact]
    public void TheLogTextDistinguishesAMissingTokenFromARefusedOne()
    {
        // Same status, two different diagnoses: "this workstation never enrolled" versus "the
        // credential it holds is not accepted". Those have different fixes and the log line is the
        // only place an operator can tell them apart.
        var attached = AgentRequestFactory.DescribeOutcome("api/v1/events", true, 401);
        var missing = AgentRequestFactory.DescribeOutcome("api/v1/events", false, 401);

        Assert.NotEqual(attached, missing);
    }
}
