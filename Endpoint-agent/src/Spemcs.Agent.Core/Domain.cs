namespace Spemcs.Agent.Core;

using System.Threading.Channels;

// ── Classification model ──────────────────────────────────────────────

/// <summary>
/// Simplified V1 Process Classification:
/// Allowed: SPEMCS components, approved Chrome browser, essential Windows infrastructure.
/// Suspicious: All other applications, unapproved browsers (Firefox, Edge), and user-space processes.
/// </summary>
public enum Classification 
{ 
    Allowed = 0, 
    Suspicious = 1,
    // Aliases for backward compatibility:
    EssentialProtected = Allowed,
    Unauthorized = Suspicious
}

/// <summary>
/// Browser families an exam may nominate as its approved examination browser.
/// <para>
/// EVERY member of this enum MUST be resolvable to a concrete, trusted executable by
/// <c>BrowserExecutableResolver</c>, because vendor firewall allow rules are scoped to that
/// executable's path. A member that cannot be resolved would leave activation with no legal
/// choice but to fail closed, so the enum is deliberately kept to exactly the families the
/// agent can both (a) locate and Authenticode-verify and (b) approve in the process
/// classifier.
/// </para>
/// <para>
/// Firefox is intentionally absent: <c>ConfigurableProcessClassifier</c> lists firefox.exe in
/// KnownUnapprovedBrowserExes and has no Firefox approval branch, so a Firefox exam would be
/// network-allowed and simultaneously reported as a process violation. The backend refuses to
/// sign <c>approved_browser = "firefox"</c> for the same reason
/// (policy_signer.SUPPORTED_APPROVED_BROWSERS).
/// </para>
/// <para>
/// Underlying values are pinned (Chrome = 0, Edge = 1) because <c>AgentSession</c> is persisted
/// to the durable state store; renumbering would silently re-point existing sessions.
/// </para>
/// </summary>
public enum ApprovedBrowserFamily
{
    Chrome = 0,
    Edge = 1
}

// ── Event model ───────────────────────────────────────────────────────

/// <summary>Minimal semantic event types for V1 monitoring.</summary>
public static class EventTypes
{
    public const string ApplicationOpened = "APPLICATION_OPENED";
    public const string ApplicationClosed = "APPLICATION_CLOSED";
    public const string UnauthorizedProcessPresent = "UNAUTHORIZED_PROCESS_PRESENT";
    public const string NetworkConnection = "NETWORK_CONNECTION";
    public const string ProhibitedProcessNetwork = "PROHIBITED_PROCESS_NETWORK";
    public const string SuspiciousPathNetwork = "SUSPICIOUS_PATH_NETWORK";
    public const string UnclassifiedProcessNetwork = "UNCLASSIFIED_PROCESS_NETWORK";
    public const string AnomalousPortViolation = "ANOMALOUS_PORT_VIOLATION";
    public const string BurstConnectionAnomaly = "BURST_CONNECTION_ANOMALY";

    /// <summary>
    /// A browser other than the one this exam approved reached the network. Distinct from
    /// <see cref="UnauthorizedProcessPresent"/> because presence alone is a lesser finding than
    /// presence plus egress: the firewall scopes the allowlist to the approved browser's image, so
    /// any other browser with an established connection is either a scoping failure or an attempt
    /// to work around it.
    /// <para>
    /// The literal contains "UNAUTHORIZED" so the backend risk engine scores it in the existing
    /// "Unauthorized Applications / Unapproved Browsers" band without a server-side change
    /// (<c>backend/services/risk_service.py</c>).
    /// </para>
    /// </summary>
    public const string UnauthorizedBrowserNetwork = "UNAUTHORIZED_BROWSER_NETWORK";
}

public enum EventDeliveryStatus { Pending, Uploading, Uploaded, Failed }
public enum EventResolutionStatus { Active = 0, Resolved = 1, Superseded = 2 }

// ── Domain records ────────────────────────────────────────────────────

public enum AgentState { Idle, PreCompliance, StudentVerification, Monitoring }

public sealed record DeviceRegistration(
    Guid DeviceId,
    string DeviceName,
    string IpAddress,
    DateTimeOffset RegisteredAtUtc);

public sealed record AgentSession(
    string SessionId,
    string? StudentRollNumber,
    DateTimeOffset StartedAtUtc,
    // Retained as a defaulted parameter ONLY for deserialization of snapshots written before the
    // field existed. Nothing reads it to make a decision - the authority on the approved browser is
    // IApprovedBrowserContext (populated from the signed policy) - so a stale Chrome here cannot
    // widen anything. AgentStateMachine.StartExam requires the value explicitly.
    ApprovedBrowserFamily ApprovedBrowser = ApprovedBrowserFamily.Chrome);

public sealed record AgentSnapshot(AgentState State, DeviceRegistration? Registration, AgentSession? Session);

public sealed record StateTransition(AgentState From, AgentState To, string Event, string? Reason, DateTimeOffset TimestampUtc);

public sealed record ProcessInfo(int ProcessId, string Name, string? ExecutablePath, int? ParentProcessId, bool HasVisibleWindow);

public sealed record ClassificationResult(
    Classification Classification,
    string Rule,
    string? Category,
    string? Publisher,
    string? Sha256,
    string? Reason = null)
{
    public bool IsAllowed => Classification == Classification.Allowed;
    public bool IsSuspicious => Classification == Classification.Suspicious;
}

public sealed record ProcessDisplayInfo(string Name, string? ExecutablePath, string Category, string? Reason);

public sealed record PreComplianceScanResult(
    bool IsClean,
    IReadOnlyList<ProcessDisplayInfo> SuspiciousProcesses,
    string StatusText);

public sealed record ViolationEvent(
    Guid EventId,
    string DeviceName,
    string? StudentRollNumber,
    string EventType,
    int ProcessId,
    string ProcessName,
    DateTimeOffset TimestampUtc,
    string? ExecutablePath = null,
    string? Reason = null,
    EventDeliveryStatus DeliveryStatus = EventDeliveryStatus.Pending,
    EventResolutionStatus ResolutionStatus = EventResolutionStatus.Active,
    string? Domain = null,
    bool DnsResolved = false,
    string? DnsResolvedIp = null,
    string? DnsConfidence = null);

// ── Backend Abstraction Interfaces ─────────────────────────────────────

public interface IRegistrationService
{
    Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress, CancellationToken cancellationToken = default);
}

public interface ISessionService
{
    Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser, CancellationToken cancellationToken = default);
    Task<bool> RegisterStudentAsync(string sessionId, string rollNumber, CancellationToken cancellationToken = default);
}

public interface IEventPublisher
{
    Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default);
}

// ── Local Mock/Stub Implementations ────────────────────────────────────

public sealed class LocalMockRegistrationService : IRegistrationService
{
    public Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress, CancellationToken cancellationToken = default)
    {
        var registration = new DeviceRegistration(Guid.NewGuid(), deviceName, ipAddress, DateTimeOffset.UtcNow);
        return Task.FromResult(registration);
    }
}

public sealed class LocalMockSessionService : ISessionService
{
    public Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser, CancellationToken cancellationToken = default) => Task.FromResult(true);
    public Task<bool> RegisterStudentAsync(string sessionId, string rollNumber, CancellationToken cancellationToken = default) => Task.FromResult(true);
}

public sealed class LocalMockEventPublisher : IEventPublisher
{
    private readonly List<ViolationEvent> _publishedEvents = [];
    public IReadOnlyList<ViolationEvent> PublishedEvents => _publishedEvents;

    public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
    {
        lock (_publishedEvents) { _publishedEvents.Add(violation); }
        return Task.CompletedTask;
    }
}

// ── Core Service Interfaces ───────────────────────────────────────────

public interface IProcessAuditSink { void Record(string action, ProcessInfo process, ClassificationResult classification); }
public sealed class NullProcessAuditSink : IProcessAuditSink { public void Record(string action, ProcessInfo process, ClassificationResult classification) { } }

public interface IAgentStore
{
    AgentSnapshot LoadSnapshot();
    void SaveRegistration(DeviceRegistration registration);
    void SaveState(AgentState state, AgentSession? session);
    void Enqueue(ViolationEvent violation);
    IReadOnlyList<ViolationEvent> GetPendingEvents(int limit = 100);
    IReadOnlyList<ViolationEvent> ClaimPendingEvents(int limit = 100, DateTimeOffset? nowUtc = null);
    void MarkUploadFailed(Guid eventId, DateTimeOffset retryAtUtc);
    int PurgeUploaded(DateTimeOffset olderThanUtc);
    IReadOnlyList<ViolationEvent> GetEvents(EventDeliveryStatus? status = null, int limit = 100);
    void MarkUploaded(Guid eventId);
    void ResolveEvent(Guid eventId, EventResolutionStatus status) { }
    IReadOnlyList<ViolationEvent> GetActiveEvents(int limit = 100) => GetEvents(limit: limit).Where(e => e.ResolutionStatus == EventResolutionStatus.Active).ToArray();
}

public sealed class NullAgentStore : IAgentStore
{
    private AgentState _state = AgentState.Idle;
    private DeviceRegistration? _reg;
    private AgentSession? _session;
    private readonly List<ViolationEvent> _events = [];

    public AgentSnapshot LoadSnapshot() => new(_state, _reg, _session);
    public void SaveRegistration(DeviceRegistration registration) => _reg = registration;
    public void SaveState(AgentState state, AgentSession? session) { _state = state; _session = session; }
    public void Enqueue(ViolationEvent violation) { lock (_events) { _events.Add(violation); } }
    public IReadOnlyList<ViolationEvent> GetPendingEvents(int limit = 100) => _events.Where(e => e.DeliveryStatus == EventDeliveryStatus.Pending).Take(limit).ToList();
    public IReadOnlyList<ViolationEvent> ClaimPendingEvents(int limit = 100, DateTimeOffset? nowUtc = null) => GetPendingEvents(limit);
    public void MarkUploadFailed(Guid eventId, DateTimeOffset retryAtUtc) { }
    public int PurgeUploaded(DateTimeOffset olderThanUtc) => 0;
    public IReadOnlyList<ViolationEvent> GetEvents(EventDeliveryStatus? status = null, int limit = 100) => _events.Take(limit).ToList();
    public void MarkUploaded(Guid eventId) { }
}

public interface IProcessSource
{
    IReadOnlyList<ProcessInfo> GetProcesses();
    ProcessInfo? FindById(int processId) => GetProcesses().FirstOrDefault(p => p.ProcessId == processId);
}
public interface IProcessClassifier { ClassificationResult Classify(ProcessInfo process); }

public interface IExamActivationSource
{
    IAsyncEnumerable<bool> ReadCommandsAsync(CancellationToken cancellationToken);
}

public interface IEventUploader
{
    Task UploadAsync(IReadOnlyList<ViolationEvent> events, CancellationToken cancellationToken);
}

public interface IExamUiGateway
{
    Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken);
    Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken);
    Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken);
    Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken);
    Task NotifySessionStartedAsync(CancellationToken cancellationToken);
    Task NotifySessionStoppedAsync(CancellationToken cancellationToken);
}

// ── State machine ─────────────────────────────────────────────────────

public sealed class AgentStateMachine
{
    private readonly IAgentStore _store;
    private readonly Action<StateTransition>? _transitionLog;

    public AgentState State { get; private set; }
    public AgentSession? Session { get; private set; }

    public AgentStateMachine(IAgentStore store, Action<StateTransition>? transitionLog = null)
    {
        _store = store;
        _transitionLog = transitionLog;
        var snapshot = store.LoadSnapshot();
        State = snapshot.State;
        Session = snapshot.Session;
    }

    /// <summary>
    /// Begins a session for <paramref name="approvedBrowser"/>.
    /// </summary>
    /// <param name="approvedBrowser">
    /// The family this session is for. Deliberately has no default: the value is persisted on the
    /// session, and a silent Chrome default would make a session record that contradicts the
    /// firewall rules actually installed for an Edge exam.
    /// </param>
    public bool StartExam(ApprovedBrowserFamily approvedBrowser)
    {
        if (State != AgentState.Idle)
        {
            Session = null;
            Transition(AgentState.Idle, "RESET_EXAM");
        }
        if (_store.LoadSnapshot().Registration is null) return Reject("START_EXAM", "Device registration is required.");
        Session = new AgentSession(Guid.NewGuid().ToString("N"), null, DateTimeOffset.UtcNow, approvedBrowser);
        Transition(AgentState.PreCompliance, "START_EXAM");
        return true;
    }

    public bool ComplianceSatisfied()
    {
        if (State != AgentState.PreCompliance || Session is null)
            return Reject("COMPLIANCE_SATISFIED", "Pre-compliance is not active.");
        Transition(AgentState.StudentVerification, "COMPLIANCE_SATISFIED");
        return true;
    }

    public bool VerifyStudent(string rollNumber)
    {
        if (State != AgentState.StudentVerification || Session is null)
            return Reject("STUDENT_VERIFICATION", "Student verification is not active.");
        if (string.IsNullOrWhiteSpace(rollNumber))
            return Reject("STUDENT_VERIFICATION", "Roll number is required.");
        Session = Session with { StudentRollNumber = rollNumber.Trim() };
        Transition(AgentState.Monitoring, "STUDENT_VERIFICATION");
        return true;
    }

    public bool StopExam()
    {
        if (State is not (AgentState.PreCompliance or AgentState.StudentVerification or AgentState.Monitoring))
            return Reject("STOP_EXAM", "No active exam session exists.");
        Session = null;
        Transition(AgentState.Idle, "STOP_EXAM");
        return true;
    }

    public AgentSnapshot Snapshot() => _store.LoadSnapshot();

    private bool Reject(string @event, string reason)
    {
        _transitionLog?.Invoke(new StateTransition(State, State, @event, reason, DateTimeOffset.UtcNow));
        return false;
    }

    private void Transition(AgentState state, string @event)
    {
        var from = State;
        State = state;
        _store.SaveState(State, Session);
        _transitionLog?.Invoke(new StateTransition(from, state, @event, null, DateTimeOffset.UtcNow));
    }
}

// ── Registration Coordinator ──────────────────────────────────────────
public sealed class RegistrationCoordinator
{
    private readonly IAgentStore _store;
    private readonly IExamUiGateway _ui;
    private readonly IRegistrationService _regService;

    public RegistrationCoordinator(IAgentStore store, IExamUiGateway ui, IRegistrationService? regService = null)
    {
        _store = store;
        _ui = ui;
        _regService = regService ?? new LocalMockRegistrationService();
    }

    public async Task<bool> EnsureRegisteredAsync(string ipAddress, CancellationToken cancellationToken)
    {
        var snapshot = _store.LoadSnapshot();
        if (snapshot.Registration is not null) return true;

        var registration = await _ui.RequestRegistrationAsync(ipAddress, cancellationToken);
        if (registration is null) return false;

        var registeredDevice = await _regService.RegisterDeviceAsync(registration.DeviceName, registration.IpAddress, cancellationToken);
        _store.SaveRegistration(registeredDevice);
        return true;
    }
}

// ── Exam Pipeline ─────────────────────────────────────────────────────
public sealed class ExamPipeline
{
    private readonly AgentStateMachine _machine;
    private readonly PreComplianceEngine _compliance;
    private readonly ProcessMonitor _monitor;
    private readonly IExamUiGateway _ui;
    private readonly IAgentStore _store;
    private readonly ISessionService _sessionService;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly IApprovedBrowserContext _approvedBrowser;

    /// <param name="approvedBrowser">
    /// Shared approved-browser context. Required, not defaulted: a hardcoded Chrome default here is
    /// what previously let the pipeline record one browser while enforcement scoped rules to
    /// another. Callers with no policy in play can pass
    /// <see cref="ApprovedBrowserContext.ForFamily"/>.
    /// </param>
    public ExamPipeline(
        AgentStateMachine machine,
        PreComplianceEngine compliance,
        ProcessMonitor monitor,
        IExamUiGateway ui,
        IApprovedBrowserContext approvedBrowser,
        IAgentStore? store = null,
        ISessionService? sessionService = null)
    {
        _machine = machine;
        _compliance = compliance;
        _monitor = monitor;
        _ui = ui;
        _store = store ?? new NullAgentStore();
        _sessionService = sessionService ?? new LocalMockSessionService();
        _approvedBrowser = approvedBrowser ?? throw new ArgumentNullException(nameof(approvedBrowser));
    }

    public AgentState State => _machine.State;

    public async Task<bool> StartAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            // Sampled once, then reused for both the local session record and the backend session,
            // so the two cannot disagree if a signed policy binds while this method is running.
            var approvedBrowser = _approvedBrowser.Effective;

            if (!_machine.StartExam(approvedBrowser)) return false;

            // 1. Launch/show UI immediately in loading state
            await _ui.ShowPreComplianceLoadingAsync(cancellationToken);

            // 2. Perform process scan in background
            var scanResult = _compliance.Scan();

            // 3. Record suspicious process events if any
            if (!scanResult.IsClean)
            {
                var snapshot = _machine.Snapshot();
                foreach (var item in scanResult.SuspiciousProcesses)
                {
                    _store.Enqueue(new ViolationEvent(
                        Guid.NewGuid(),
                        snapshot.Registration?.DeviceName ?? "UNKNOWN",
                        snapshot.Session?.StudentRollNumber,
                        EventTypes.UnauthorizedProcessPresent,
                        0,
                        item.Name,
                        DateTimeOffset.UtcNow,
                        item.ExecutablePath,
                        item.Reason));
                }
            }

            // 4. Update UI with scan results and wait for Continue
            await _ui.UpdatePreComplianceResultAsync(scanResult, cancellationToken);

            // 5. Transition to Student Verification
            if (!_machine.ComplianceSatisfied()) { _machine.StopExam(); return false; }

            // 6. Request student verification roll number
            var rollNumber = await _ui.RequestStudentVerificationAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(rollNumber) || !_machine.VerifyStudent(rollNumber))
            {
                _machine.StopExam();
                await _ui.NotifySessionStoppedAsync(cancellationToken);
                return false;
            }

            // 7. Register session with backend service abstraction
            await _sessionService.StartExamSessionAsync(_machine.Session!.SessionId, approvedBrowser, cancellationToken);
            await _sessionService.RegisterStudentAsync(_machine.Session!.SessionId, rollNumber, cancellationToken);

            // 8. Exit UI & start continuous monitoring
            await _ui.NotifySessionStartedAsync(cancellationToken);
            _monitor.Start();
            return true;
        }
        catch
        {
            _machine.StopExam();
            await _ui.NotifySessionStoppedAsync(cancellationToken);
            return false;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> StopAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _monitor.Stop();
            var stopped = _machine.StopExam();
            await _ui.NotifySessionStoppedAsync(cancellationToken);
            return stopped;
        }
        finally
        {
            _gate.Release();
        }
    }
}
