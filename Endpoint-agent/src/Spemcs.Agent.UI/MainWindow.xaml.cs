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
        _classifier = new ConfigurableProcessClassifier();
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

                // Self-Heal: Bootstrap Device Token if missing
                if (string.IsNullOrWhiteSpace(_config.DeviceToken))
                {
                    try
                    {
                        var bootstrapRes = await _http.PostAsJsonAsync("api/devices/register", new
                        {
                            device_name = _deviceName,
                            hardware_uuid = _deviceName,
                            enrollment_key = "spemcs-enrollment-bootstrap-key-default"
                        }, cancellationToken);

                        if (bootstrapRes.IsSuccessStatusCode)
                        {
                            var regData = await bootstrapRes.Content.ReadFromJsonAsync<DeviceRegistrationResponse>(cancellationToken: cancellationToken);
                            if (regData != null && !string.IsNullOrWhiteSpace(regData.DeviceToken))
                            {
                                _config.DeviceToken = regData.DeviceToken;
                                new AgentConfigService().Save(_config);
                            }
                        }
                    }
                    catch (Exception bootEx)
                    {
                        LogUi($"Bootstrap registration exception: {bootEx.Message}");
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
                            var actResult = await _enforcementService.ApplyPolicyAsync(sessGuid, examId, signedMsgPayload, targetProfiles: 6, cancellationToken: cancellationToken);
                            LogUi($"[EnforcementService] ApplyPolicy: Success={actResult.Success}, State={actResult.State}, Reason={actResult.FailureReason}, RulesInstalled={actResult.InstalledRuleCount}");
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
                approvedBrowser = "Chrome"
            };
            await _http.PostAsJsonAsync("api/v1/sessions/start", startReq);
        }
        catch { }

        // 2. Start Live Background Process Monitor
        var eventPublisher = new InlineEventPublisher(_http);
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

public class InlineEventPublisher : IEventPublisher
{
    private readonly HttpClient _http;

    public InlineEventPublisher(HttpClient http) => _http = http;

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
            await _http.PostAsJsonAsync("api/v1/events", req, cancellationToken);
        }
        catch { }
    }
}
