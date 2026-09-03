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

    public string DeviceName => _deviceName;
    public string RollNumber => RollNumberBox.Text.Trim();

    public MainWindow(AgentConfig? config = null)
    {
        InitializeComponent();

        _config = config ?? new AgentConfigService().Load() ?? new AgentConfig();
        _backendUrl = _config.ServerUrl;
        _deviceName = _config.DeviceName;

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
        _wsCts?.Cancel();
        _wsCts = new CancellationTokenSource();
        _ = Task.Run(() => ConnectCentralWebSocketAsync(_wsCts.Token));
    }

    private async Task ConnectCentralWebSocketAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var ws = new ClientWebSocket();
                var wsUrl = _backendUrl.Replace("http://", "ws://").Replace("https://", "wss://").TrimEnd('/') + "/api/v1/ws/agent";
                await ws.ConnectAsync(new Uri(wsUrl), cancellationToken);

                // Handshake with Central Server
                var registerMsg = JsonSerializer.Serialize(new
                {
                    action = "REGISTER",
                    hardware_uuid = _deviceName
                });
                var bytes = Encoding.UTF8.GetBytes(registerMsg);
                await ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, cancellationToken);

                var buffer = new byte[8192];
                while (ws.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
                {
                    var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
                    if (result.MessageType == WebSocketMessageType.Close) break;

                    var json = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    string action = "";
                    if (root.TryGetProperty("action", out var actionProp))
                        action = actionProp.GetString() ?? "";
                    else if (root.TryGetProperty("type", out var typeProp))
                        action = typeProp.GetString() ?? "";

                    // When Central Server Activates Exam: Surface and Run Pre-Compliance Scan
                    if (action.Equals("LAUNCH_EXAM_MODE", StringComparison.OrdinalIgnoreCase) ||
                        action.Equals("START_EXAM", StringComparison.OrdinalIgnoreCase))
                    {
                        Dispatcher.Invoke(() =>
                        {
                            SurfaceScreenLock();
                            _ = RunPreComplianceScanAsync();
                        });
                    }
                    else if (action.Equals("STOP_EXAM_MODE", StringComparison.OrdinalIgnoreCase) ||
                             action.Equals("STOP_EXAM", StringComparison.OrdinalIgnoreCase))
                    {
                        Dispatcher.Invoke(() =>
                        {
                            _monitor?.Stop();
                            Hide();
                        });
                    }
                }
            }
            catch
            {
                // Reconnect with backoff
                await Task.Delay(3000, cancellationToken);
            }
        }
    }

    private void SurfaceScreenLock()
    {
        WindowState = WindowState.Maximized;
        WindowStyle = WindowStyle.None;
        ResizeMode = ResizeMode.NoResize;
        Topmost = true;
        ShowInTaskbar = false;
        Visibility = Visibility.Visible;
        Show();
        Activate();
        Focus();
    }

    public async Task RunPreComplianceScanAsync()
    {
        HeaderTitle.Text = "Pre-compliance check";
        HeaderSubtitle.Text = "Verifying running applications against exam policy";
        AccentBar.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E5E0D8"));

        LoadingPanel.Visibility = Visibility.Visible;
        PreComplianceResultPanel.Visibility = Visibility.Collapsed;
        StudentVerificationPanel.Visibility = Visibility.Collapsed;

        var scan = await Task.Run(() => _compliance.Scan());

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
