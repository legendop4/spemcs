using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Ipc;
using Spemcs.Agent.UI.Models;
using Spemcs.Agent.UI.Services;

namespace Spemcs.Agent.UI;

public partial class MainWindow : Window
{
    private readonly string _backendUrl;
    private readonly HttpClient _http;
    private readonly SqliteAgentStore _store;
    private readonly PreComplianceEngine _compliance;
    private readonly WindowsProcessSource _source;
    private readonly ConfigurableProcessClassifier _classifier;
    private readonly AgentConfig _config;

    /// <summary>
    /// The UI runs in the interactive desktop session, in a DIFFERENT process from the Windows
    /// service, so it cannot share the service's DI singleton. It keeps its own context, seeded from
    /// the shared config.json and then bound to the signed family once the service reports that it
    /// verified and applied the policy this UI forwarded (see the SIGNED_NETWORK_POLICY branch).
    /// </summary>
    private readonly ApprovedBrowserContext _approvedBrowser;

    private ProcessMonitor? _monitor;
    private string _deviceName;
    private string _rollNumber = "2301921540174";
    private string _sessionId = Guid.NewGuid().ToString("N");
    private CancellationTokenSource? _wsCts;

    private readonly IEnforcementServiceClient _enforcementService = new EnforcementServiceClient();

    public string DeviceName => _deviceName;
    public string RollNumber => RollNumberBox.Text.Trim();

    public static void LogUi(string message)
    {
        try
        {
            var dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs", "Logs");
            System.IO.Directory.CreateDirectory(dir);
            var file = System.IO.Path.Combine(dir, "agent_ui.log");
            System.IO.File.AppendAllText(file, $"[{DateTime.UtcNow:O}] [PID {Environment.ProcessId}] {message}{Environment.NewLine}");
        }
        catch { }
    }

    public MainWindow(AgentConfig? config = null)
    {
        InitializeComponent();

        _config = config ?? new AgentConfigService().Load() ?? new AgentConfig();
        _backendUrl = _config.ServerUrl;
        _deviceName = _config.DeviceName;

        LogUi($"MainWindow initialized for {_deviceName} targeting {_backendUrl}");

        _http = new HttpClient
        {
            BaseAddress = new Uri(_backendUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(10)
        };

        var dataDir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs");
        _store = new SqliteAgentStore(dataDir);
        _source = new WindowsProcessSource();

        if (ApprovedBrowserFamilies.TryParse(_config.ApprovedBrowser, out var configuredFamily))
        {
            _approvedBrowser = new ApprovedBrowserContext(configuredFamily, "config.json 'approvedBrowser'");
        }
        else
        {
            _approvedBrowser = new ApprovedBrowserContext(
                ApprovedBrowserFamily.Chrome,
                string.IsNullOrWhiteSpace(_config.ApprovedBrowser)
                    ? "built-in fallback (no 'approvedBrowser' in config.json)"
                    : $"built-in fallback (config.json 'approvedBrowser' = '{_config.ApprovedBrowser}' is not a supported family)");
        }

        LogUi($"Provisional approved browser: {_approvedBrowser.Current.Family} from {_approvedBrowser.Current.Reason}");

        _classifier = new ConfigurableProcessClassifier(_approvedBrowser);
        _compliance = new PreComplianceEngine(_source, _classifier);

        // Start persistent background WebSocket listener
        StartWebSocketListener();
    }

    private void StartWebSocketListener()
    {
        LogUi("StartWebSocketListener starting worker task.");
        _wsCts?.Cancel();
        _wsCts = new CancellationTokenSource();
        _ = Task.Run(() => ConnectCentralWebSocketAsync(_wsCts.Token));
    }

    private async Task ConnectCentralWebSocketAsync(CancellationToken cancellationToken)
    {
        LogUi($"ConnectCentralWebSocketAsync starting. Backend: {_backendUrl}");
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var ws = new ClientWebSocket();
                var wsUri = new Uri(_backendUrl.Replace("http://", "ws://").Replace("https://", "wss://").TrimEnd('/') + "/api/v1/ws/agent");

                LogUi($"Connecting to {wsUri}...");
                await ws.ConnectAsync(wsUri, cancellationToken);
                LogUi($"WebSocket connected! State={ws.State}");

                // Self-heal: re-enrol if config.json carries no device token.
                //
                // This block was previously incapable of working and its failure was invisible. It
                // posted to `api/devices/register`, which does not exist (the route is
                // `api/v1/devices/register`), with snake_case field names the DeviceRegisterReq
                // schema does not declare, and with the backend's committed placeholder enrolment key
                // written as a literal - publishing that secret in every installed copy of this
                // application while also breaking any deployment that had changed it. A non-success
                // response was then discarded without a log line.
                //
                // It now goes through the same CentralApiClient the setup wizard uses, so there is
                // one registration code path with one enrolment-key source.
                if (string.IsNullOrWhiteSpace(_config.DeviceToken))
                {
                    try
                    {
                        var enrollmentKey = EnrollmentKeyProvider.Resolve();
                        if (string.IsNullOrWhiteSpace(enrollmentKey))
                        {
                            LogUi("Self-heal registration skipped: no enrollment key is configured on this workstation.");
                        }
                        else
                        {
                            var regData = await new CentralApiClient().RegisterDeviceAsync(
                                _backendUrl,
                                new DeviceRegistrationRequest
                                {
                                    DeviceName = _deviceName,
                                    HardwareUuid = string.IsNullOrWhiteSpace(_config.HardwareUuid)
                                        ? _deviceName
                                        : _config.HardwareUuid,
                                    LabId = _config.LabId,
                                    PcNumber = _config.PcNumber,
                                    Hostname = Environment.MachineName,
                                    EnrollmentKey = enrollmentKey,
                                },
                                cancellationToken).ConfigureAwait(false);

                            if (!string.IsNullOrWhiteSpace(regData.DeviceToken))
                            {
                                _config.DeviceToken = regData.DeviceToken;
                                new AgentConfigService().Save(_config);
                                LogUi($"Self-heal registration succeeded for {_deviceName}; device token stored.");
                            }
                            else
                            {
                                LogUi("Self-heal registration returned no device token.");
                            }
                        }
                    }
                    catch (Exception bootEx)
                    {
                        LogUi($"Self-heal registration failed: {bootEx.Message}");
                    }
                }

                // Handshake with Central Server
                var registerMsg = JsonSerializer.Serialize(new
                {
                    action = "REGISTER",
                    hardware_uuid = _deviceName,
                    device_token = _config.DeviceToken
                });
                var bytes = Encoding.UTF8.GetBytes(registerMsg);
                await ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, cancellationToken);
                LogUi($"Sent REGISTER payload for {_deviceName}");

                var buffer = new byte[8192];
                while (ws.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
                {
                    var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        LogUi("WebSocket closed by remote endpoint.");
                        break;
                    }

                    var json = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    LogUi($"Received WebSocket frame ({result.Count} bytes): {json}");
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    string action = "";
                    if (root.TryGetProperty("action", out var actionProp))
                        action = actionProp.GetString() ?? "";
                    else if (root.TryGetProperty("type", out var typeProp))
                        action = typeProp.GetString() ?? "";
                    else if (root.TryGetProperty("message_type", out var msgTypeProp))
                        action = msgTypeProp.GetString() ?? "";

                    LogUi($"Action recognized: '{action}'");

                    // When Central Server Activates Exam: Surface and Run Pre-Compliance Scan
                    if (action.Equals("LAUNCH_EXAM_MODE", StringComparison.OrdinalIgnoreCase) ||
                        action.Equals("START_EXAM", StringComparison.OrdinalIgnoreCase))
                    {
                        LogUi("Triggering SurfaceScreenLock and RunPreComplianceScanAsync via Dispatcher...");
                        Dispatcher.Invoke(() =>
                        {
                            try
                            {
                                SurfaceScreenLock();
                                _ = RunPreComplianceScanAsync();
                            }
                            catch (Exception dispEx)
                            {
                                LogUi($"Dispatcher exception during LAUNCH_EXAM_MODE: {dispEx}");
                            }
                        });
                    }
                    else if (action.Equals("STOP_EXAM_MODE", StringComparison.OrdinalIgnoreCase) ||
                             action.Equals("STOP_EXAM", StringComparison.OrdinalIgnoreCase))
                    {
                        LogUi("STOP_EXAM_MODE received.");
                        if (Guid.TryParse(_sessionId, out var sessGuid))
                        {
                            try
                            {
                                var stopRes = await _enforcementService.RemovePolicyAsync(sessGuid, "Exam stopped", cancellationToken);
                                LogUi($"[EnforcementService] RemovePolicy: Success={stopRes.Success}, State={stopRes.State}, Reason={stopRes.FailureReason}");

                                if (stopRes.Success && _approvedBrowser.ReleaseSignedPolicy(sessGuid))
                                {
                                    LogUi($"Approved-browser binding released for session {sessGuid}; reverting to {_approvedBrowser.Effective}.");
                                }
                            }
                            catch (Exception ex)
                            {
                                LogUi($"[EnforcementService] RemovePolicy error: {ex.Message}");
                            }
                        }
                        Dispatcher.Invoke(() =>
                        {
                            _monitor?.Stop();
                            Hide();
                        });
                    }
                    else if (action.Equals("SIGNED_NETWORK_POLICY", StringComparison.OrdinalIgnoreCase) ||
                             action.Equals("UPDATE_EXAM_POLICY", StringComparison.OrdinalIgnoreCase))
                    {
                        var signedMsgPayload = new SignedPolicyMessagePayload(
                            root.GetProperty("message_type").GetString() ?? "",
                            root.GetProperty("protocol_version").GetInt32(),
                            root.GetProperty("raw_policy_json").GetString() ?? "",
                            root.GetProperty("signature_base64").GetString() ?? ""
                        );

                        // Parse exam_id from raw_policy_json
                        using var pDoc = JsonDocument.Parse(signedMsgPayload.RawPolicyJson);
                        var examIdStr = pDoc.RootElement.GetProperty("exam_id").GetString();
                        var examId = Guid.Parse(examIdStr!);

                        var sessGuid = Guid.TryParse(_sessionId, out var parsedGuid) ? parsedGuid : Guid.NewGuid();

                        if (action.Equals("SIGNED_NETWORK_POLICY", StringComparison.OrdinalIgnoreCase))
                        {
                            LogUi($"Forwarding SIGNED_NETWORK_POLICY to Service over named pipe: Session={sessGuid}, Exam={examId}");
                            // Requirement 6: Domain|Private|Public. Named via the enum rather than
                            // written as a literal so this call site cannot drift from the IPC
                            // default the way the old hardcoded 6 did.
                            var actResult = await _enforcementService.ApplyPolicyAsync(sessGuid, examId, signedMsgPayload, targetProfiles: (int)FirewallProfiles.All, cancellationToken: cancellationToken);
                            LogUi($"[EnforcementService] ApplyPolicy: Success={actResult.Success}, State={actResult.State}, Reason={actResult.FailureReason}, RulesInstalled={actResult.InstalledRuleCount}");

                            // Adopt the approved browser ONLY after the service reports success.
                            // The UI does not verify signatures itself; success means the service
                            // verified this exact raw_policy_json, so reading approved_browser out of
                            // the same bytes carries that verification. Reading it before the apply,
                            // or after a failure, would let an unsigned WebSocket frame steer the
                            // monitor's idea of which browser is approved.
                            if (actResult.Success)
                            {
                                AdoptSignedApprovedBrowser(sessGuid, pDoc.RootElement);
                            }
                        }
                        else
                        {
                            LogUi($"Forwarding UPDATE_EXAM_POLICY to Service over named pipe: Session={sessGuid}, Exam={examId}");
                            var updResult = await _enforcementService.UpdatePolicyAsync(sessGuid, examId, signedMsgPayload, cancellationToken: cancellationToken);
                            LogUi($"[EnforcementService] UpdatePolicy: Success={updResult.Success}, State={updResult.State}, Reason={updResult.FailureReason}, RulesInstalled={updResult.InstalledRuleCount}");
                        }
                    }
                    else if (action.Equals("HEARTBEAT_PING", StringComparison.OrdinalIgnoreCase))
                    {
                        var pongMsg = JsonSerializer.Serialize(new { action = "HEARTBEAT_PONG" });
                        var pongBytes = Encoding.UTF8.GetBytes(pongMsg);
                        await ws.SendAsync(new ArraySegment<byte>(pongBytes), WebSocketMessageType.Text, true, cancellationToken);
                    }
                }
            }
            catch (Exception loopEx)
            {
                LogUi($"WebSocket connection loop error: {loopEx}");
                // Reconnect with backoff
                await Task.Delay(3000, cancellationToken);
            }
        }
    }

    /// <summary>
    /// Adopts the <c>approved_browser</c> of a signed policy the SERVICE has already accepted, so the
    /// UI's process classifier judges browsers the same way the installed firewall rules do.
    /// <para>
    /// Only ever called after <c>ApplyPolicyAsync</c> returned success for these exact bytes. The UI
    /// verifies no signatures of its own; the service's success is the whole basis for trusting this
    /// field, which is why it is read from <paramref name="policyRoot"/> - the parsed
    /// <c>raw_policy_json</c> that was verified - and not from the enclosing WebSocket frame, whose
    /// other fields are unauthenticated.
    /// </para>
    /// <para>
    /// Every outcome is logged. A silent failure here would leave the classifier on its provisional
    /// family while the firewall enforced a different one - the precise mismatch
    /// <see cref="IApprovedBrowserContext"/> exists to prevent - and that must be visible in the log
    /// rather than inferred from later misclassifications.
    /// </para>
    /// </summary>
    private void AdoptSignedApprovedBrowser(Guid sessionId, JsonElement policyRoot)
    {
        try
        {
            if (!policyRoot.TryGetProperty("approved_browser", out var browserProp)
                || browserProp.ValueKind != JsonValueKind.String)
            {
                // Not fatal for the UI: enforcement already succeeded, and the service validated the
                // field on its own side. The classifier simply keeps its provisional family.
                LogUi($"Signed policy for session {sessionId} carries no 'approved_browser' string; " +
                      $"monitor keeps provisional {_approvedBrowser.Effective}.");
                return;
            }

            var rawBrowser = browserProp.GetString();

            if (!ApprovedBrowserFamilies.TryParse(rawBrowser, out var signedFamily))
            {
                LogUi($"Signed policy for session {sessionId} names unsupported approved_browser " +
                      $"'{rawBrowser}'; monitor keeps provisional {_approvedBrowser.Effective}.");
                return;
            }

            if (_approvedBrowser.BindSignedPolicy(sessionId, signedFamily, $"signed policy for session {sessionId}"))
            {
                LogUi($"Approved browser bound from signed policy: {signedFamily} (session {sessionId}).");
            }
            else
            {
                // Another session still holds the binding - a stop was missed somewhere. Say so
                // loudly: the classifier is now judging against a different exam's browser.
                LogUi($"WARNING: could not bind approved browser {signedFamily} for session {sessionId}; " +
                      $"binding is still held by session {_approvedBrowser.Current.SessionId}. " +
                      $"Monitor continues to use {_approvedBrowser.Effective}.");
            }
        }
        catch (Exception ex)
        {
            LogUi($"Failed to adopt approved browser from signed policy for session {sessionId}: {ex.Message}");
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private void SurfaceScreenLock()
    {
        LogUi($"SurfaceScreenLock invoked. Initial: WindowState={WindowState}, Visibility={Visibility}, IsVisible={IsVisible}");
        WindowState = WindowState.Maximized;
        WindowStyle = WindowStyle.None;
        ResizeMode = ResizeMode.NoResize;
        Topmost = true;
        ShowInTaskbar = false;
        Visibility = Visibility.Visible;
        Show();
        Activate();
        Focus();
        var helper = new System.Windows.Interop.WindowInteropHelper(this);
        if (helper.Handle != IntPtr.Zero)
        {
            SetForegroundWindow(helper.Handle);
        }
        LogUi($"SurfaceScreenLock completed. Current: WindowState={WindowState}, Visibility={Visibility}, IsVisible={IsVisible}, HWND={helper.Handle:X}");
    }

    public async Task RunPreComplianceScanAsync()
    {
        LogUi("RunPreComplianceScanAsync started.");
        try
        {
            HeaderTitle.Text = "Pre-compliance check";
            HeaderSubtitle.Text = "Verifying running applications against exam policy";
            AccentBar.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E5E0D8"));

            LoadingPanel.Visibility = Visibility.Visible;
            PreComplianceResultPanel.Visibility = Visibility.Collapsed;
            StudentVerificationPanel.Visibility = Visibility.Collapsed;

            LogUi("RunPreComplianceScanAsync starting scan Task.Run...");
            var scan = await Task.Run(() => _compliance.Scan());
            LogUi($"RunPreComplianceScanAsync scan finished: Clean={scan.IsClean}, Suspicious={scan.SuspiciousProcesses.Count}");

            LoadingPanel.Visibility = Visibility.Collapsed;
            PreComplianceResultPanel.Visibility = Visibility.Visible;

            if (scan.IsClean)
            {
                HeaderSubtitle.Text = "System verified clean. No forbidden background processes detected.";
                AccentBar.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981"));
                StatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EDF7ED"));
                StatusBadge.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#C8E6C9"));
                StatusBadgeText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2E7D32"));
                StatusBadgeText.Text = "Pre-Compliance Check Passed. All running processes comply with examination security.";
                SuspiciousProcessList.Visibility = Visibility.Collapsed;
            }
            else
            {
                HeaderSubtitle.Text = "Unapproved applications detected on this device";
                AccentBar.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E5E0D8"));
                StatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFF0F0"));
                StatusBadge.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F8C8C8"));
                StatusBadgeText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#901C1C"));
                StatusBadgeText.Text = $"⚠  {scan.SuspiciousProcesses.Count} unapproved applications detected. Close them before starting the exam.";
                SuspiciousProcessList.ItemsSource = scan.SuspiciousProcesses;
                SuspiciousProcessList.Visibility = Visibility.Visible;
            }
            LogUi("RunPreComplianceScanAsync completed UI update.");
        }
        catch (Exception scanEx)
        {
            LogUi($"RunPreComplianceScanAsync exception: {scanEx}");
        }
    }

    public void TransitionToStudentVerification()
    {
        HeaderTitle.Text = "Candidate verification";
        HeaderSubtitle.Text = "Enter candidate credentials to initialize monitored session";
        AccentBar.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E5E0D8"));

        LoadingPanel.Visibility = Visibility.Collapsed;
        PreComplianceResultPanel.Visibility = Visibility.Collapsed;
        StudentVerificationPanel.Visibility = Visibility.Visible;

        RollNumberBox.Focus();
        RollNumberBox.SelectAll();
    }

    public async Task StartActiveMonitoringSessionAsync()
    {
        _rollNumber = RollNumberBox.Text.Trim();
        _sessionId = Guid.NewGuid().ToString("N");

        var session = new AgentSession(_sessionId, _rollNumber, DateTimeOffset.UtcNow);
        _store.SaveState(AgentState.Monitoring, session);

        // 1. Notify Central Server of Session Start
        try
        {
            var startReq = new
            {
                sessionId = _sessionId,
                studentRollNumber = _rollNumber,
                // Reported, not chosen: the wire value of whatever family is effective right now
                // (host configuration at this point - a signed policy has not arrived yet). Sending a
                // hardcoded "Chrome" here made the server's record of the session disagree with what
                // this agent was actually monitoring for on an Edge exam.
                approvedBrowser = ApprovedBrowserFamilies.ToWireValue(_approvedBrowser.Effective)
            };
            // The device token is REQUIRED here: /api/v1/sessions/start is gated by
            // require_device, and this call used to be posted with no credential at all, so it was
            // answered 401 and the failure was discarded by the empty catch below. The session then
            // existed only on this workstation - no server-side row, so nothing to attribute later
            // violations to.
            using var message = AgentRequestFactory.CreateJsonPost(
                "api/v1/sessions/start", startReq, _config.DeviceToken);
            using var response = await _http.SendAsync(message).ConfigureAwait(true);

            LogUi(AgentRequestFactory.DescribeOutcome(
                "api/v1/sessions/start",
                !string.IsNullOrWhiteSpace(_config.DeviceToken),
                (int)response.StatusCode));
        }
        catch (Exception ex)
        {
            // Still non-fatal - monitoring must start even if the server never hears about the
            // session - but no longer silent. The previous `catch { }` is why a 401 here left no
            // trace on the workstation.
            LogUi($"api/v1/sessions/start failed: {ex.Message}");
        }

        // 2. Start Live Background Process Monitor
        //
        // The token is read through a delegate rather than captured by value because the WebSocket
        // self-heal path can write a freshly issued token into _config while monitoring is already
        // running. A captured null would keep every subsequent event unauthenticated for the rest of
        // the session.
        var eventPublisher = new InlineEventPublisher(_http, () => _config.DeviceToken);
        _monitor = new ProcessMonitor(
            _source,
            _classifier,
            _store,
            () => new AgentSnapshot(AgentState.Monitoring, new DeviceRegistration(Guid.NewGuid(), _deviceName, "127.0.0.1", DateTimeOffset.UtcNow), session),
            eventPublisher);

        _monitor.Start();

        // 3. Hide modal shield so student can take exam in Chrome
        Hide();
    }

    private void PreComplianceContinueButton_Click(object sender, RoutedEventArgs e)
    {
        TransitionToStudentVerification();
    }

    private async void VerifyStudentButton_Click(object sender, RoutedEventArgs e)
    {
        await StartActiveMonitoringSessionAsync();
    }

    private void RollNumberBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (VerifyStudentButton != null)
            VerifyStudentButton.IsEnabled = !string.IsNullOrWhiteSpace(RollNumber);
    }

    protected override void OnClosed(EventArgs e)
    {
        _wsCts?.Cancel();
        _monitor?.Stop();
        base.OnClosed(e);
    }
}

/// <summary>
/// Publishes violation events from the UI process directly over HTTP.
/// </summary>
/// <remarks>
/// This class is the reason the backend logged a stream of
/// <c>POST /api/v1/events -&gt; 401 Unauthorized</c>: it posted through a bare
/// <see cref="HttpClient"/> that carried no <c>X-Device-Token</c>, and then discarded the refusal in
/// an empty catch. Every violation this agent detected was rejected, and nothing on the workstation
/// or the dashboard said so.
/// </remarks>
public class InlineEventPublisher : IEventPublisher
{
    private readonly HttpClient _http;
    private readonly Func<string?> _deviceTokenAccessor;

    /// <param name="deviceTokenAccessor">
    /// Read per request, not captured once: the token can be issued after monitoring has already
    /// started (the WebSocket self-heal path), and a value captured at construction would be stale
    /// for the rest of the session.
    /// </param>
    public InlineEventPublisher(HttpClient http, Func<string?> deviceTokenAccessor)
    {
        _http = http;
        _deviceTokenAccessor = deviceTokenAccessor;
    }

    public async Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
    {
        try
        {
            var req = new
            {
                eventId = violation.EventId.ToString(),
                deviceName = violation.DeviceName,
                studentRollNumber = violation.StudentRollNumber,
                eventType = violation.EventType,
                processId = violation.ProcessId,
                processName = violation.ProcessName,
                timestampUtc = violation.TimestampUtc.ToString("o"),
                executablePath = violation.ExecutablePath,
                reason = violation.Reason
            };

            var token = _deviceTokenAccessor();
            using var message = AgentRequestFactory.CreateJsonPost("api/v1/events", req, token);
            using var response = await _http.SendAsync(message, cancellationToken).ConfigureAwait(false);

            // Only failures are logged. A monitored session generates an event per process
            // transition, so logging successes would grow the file without adding information -
            // whereas a 401 or 403 here means violations are being silently dropped, which is the
            // one outcome nobody can afford to have gone unrecorded.
            if (!response.IsSuccessStatusCode)
            {
                MainWindow.LogUi(AgentRequestFactory.DescribeOutcome(
                    "api/v1/events",
                    !string.IsNullOrWhiteSpace(token),
                    (int)response.StatusCode));
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            // Transport failure. Non-fatal by design - monitoring continues and the event is lost -
            // but recorded, unlike the previous `catch { }`.
            MainWindow.LogUi($"api/v1/events transport failure: {ex.Message}");
        }
    }
}
