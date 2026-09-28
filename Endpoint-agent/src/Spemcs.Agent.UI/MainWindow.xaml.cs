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
using System.IO;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Ipc;
using Spemcs.Agent.UI.Models;
using Spemcs.Agent.UI.Services;
using Spemcs.Agent.UI.Views;

namespace Spemcs.Agent.UI;

public partial class MainWindow : Window
{
    private readonly string _backendUrl;
    private readonly HttpClient _http;
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

    private string _deviceName;
    private string _rollNumber = "2301921540174";
    private string _sessionId = Guid.NewGuid().ToString("N");

    private readonly IEnforcementServiceClient _enforcementService = new EnforcementServiceClient();
    private CancellationTokenSource? _pipeCts;
    private System.IO.Pipes.NamedPipeClientStream? _activePipeClient;

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

        // Start background IPC pipe connection to Windows Service
        StartAgentPipeListener();
        StartUiSetupPipeListener();
    }

    private void StartUiSetupPipeListener()
    {
        var ct = _pipeCts?.Token ?? CancellationToken.None;
        Task.Run(async () =>
        {
            LogUi("Starting UI Setup IPC server (PipeNames.UiSetup)...");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await using var server = PipeProtocol.CreateServer(PipeNames.UiSetup);
                    await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                    using var reader = new StreamReader(server, Encoding.UTF8);
                    var line = await reader.ReadLineAsync().ConfigureAwait(false);
                    if (string.Equals(line?.Trim(), "SHOW_SETUP", StringComparison.OrdinalIgnoreCase))
                    {
                        Dispatcher.Invoke(() =>
                        {
                            LogUi($"[UI_SETUP_REQUESTED] source=SHOW_SETUP_PIPE, pid={Environment.ProcessId}");
                            var currentConfig = new AgentConfigService().Load();
                            bool isAlreadyEnrolled = currentConfig != null && currentConfig.IsEnrolled && currentConfig.IsValid();

                            LogUi($"[ENROLLMENT_STATE_EVALUATED] source=SHOW_SETUP_PIPE, enrolled={isAlreadyEnrolled}, hasDeviceId={!string.IsNullOrWhiteSpace(currentConfig?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(currentConfig?.DeviceToken)}, configPath={new AgentConfigService().ConfigFilePath}, pid={Environment.ProcessId}");

                            if (isAlreadyEnrolled)
                            {
                                LogUi($"[UI_SETUP_SUPPRESSED] reason=ALREADY_ENROLLED, source=SHOW_SETUP_PIPE, enrolled=true, hasDeviceId={!string.IsNullOrWhiteSpace(currentConfig!.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(currentConfig.DeviceToken)}, pid={Environment.ProcessId}");
                                return;
                            }

                            LogUi($"[UI_SETUP_WINDOW_SHOWN] reason=UNENROLLED, source=SHOW_SETUP_PIPE, enrolled=false, hasDeviceId={!string.IsNullOrWhiteSpace(currentConfig?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(currentConfig?.DeviceToken)}, pid={Environment.ProcessId}");
                            var wizard = new SetupWizardWindow();
                            wizard.Topmost = true;
                            wizard.Focus();
                            wizard.ShowDialog();
                        });
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    LogUi($"UI Setup IPC server error: {ex.Message}");
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                }
            }
        });
    }

    private void StartAgentPipeListener()
    {
        _pipeCts = new CancellationTokenSource();
        var ct = _pipeCts.Token;

        Task.Run(async () =>
        {
            LogUi("Starting background listener for Agent Service IPC (PipeNames.Agent)...");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var client = PipeProtocol.CreateClient(PipeNames.Agent);
                    await client.ConnectAsync(ct).ConfigureAwait(false);
                    LogUi($"[UI_PIPE_CONNECTED] Connected to Agent Service pipe {PipeNames.Agent}. pid={Environment.ProcessId}");
                    _activePipeClient = client;

                    while (!ct.IsCancellationRequested && client.IsConnected)
                    {
                        var envelope = await PipeProtocol.ReadAsync(client, ct).ConfigureAwait(false);
                        if (envelope == null) break;

                        LogUi($"Received pipe envelope: {envelope.Type}");

                        switch (envelope.Type)
                        {
                            case MessageTypes.RequestRegistration:
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    LogUi($"[UI_SETUP_REQUESTED] source=IPC_SERVICE, pid={Environment.ProcessId}");
                                    var currentConfig = new AgentConfigService().Load();
                                    bool isAlreadyEnrolled = currentConfig != null && currentConfig.IsEnrolled && currentConfig.IsValid();

                                    LogUi($"[ENROLLMENT_STATE_EVALUATED] source=IPC_SERVICE, enrolled={isAlreadyEnrolled}, hasDeviceId={!string.IsNullOrWhiteSpace(currentConfig?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(currentConfig?.DeviceToken)}, configPath={new AgentConfigService().ConfigFilePath}, pid={Environment.ProcessId}");

                                    if (isAlreadyEnrolled)
                                    {
                                        LogUi($"[UI_SETUP_SUPPRESSED] reason=ALREADY_ENROLLED, source=IPC_SERVICE, enrolled=true, hasDeviceId={!string.IsNullOrWhiteSpace(currentConfig!.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(currentConfig.DeviceToken)}, pid={Environment.ProcessId}");
                                        var payload = new RegistrationPayload(
                                            currentConfig.DeviceName,
                                            "127.0.0.1",
                                            Guid.TryParse(currentConfig.DeviceId, out var gid) ? gid : null,
                                            currentConfig.DeviceToken
                                        );
                                        _ = Task.Run(async () =>
                                        {
                                            try
                                            {
                                                await PipeProtocol.WriteAsync(client, MessageTypes.RegistrationData, payload, ct);
                                                LogUi("[REGISTRATION_REPLIED] Sent existing authoritative registration data back to Service via pipe");
                                            }
                                            catch (Exception ex)
                                            {
                                                LogUi($"Failed to reply registration data: {ex.Message}");
                                            }
                                        });
                                        return;
                                    }

                                    LogUi($"[UI_SETUP_WINDOW_SHOWN] reason=UNENROLLED, source=IPC_SERVICE, enrolled=false, hasDeviceId={!string.IsNullOrWhiteSpace(currentConfig?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(currentConfig?.DeviceToken)}, pid={Environment.ProcessId}");
                                    var wizard = new SetupWizardWindow();
                                    wizard.Topmost = true;
                                    wizard.Focus();
                                    var res = wizard.ShowDialog();
                                    if (res == true)
                                    {
                                        var freshlySavedConfig = new AgentConfigService().Load();
                                        var payload = new RegistrationPayload(
                                            freshlySavedConfig?.DeviceName ?? Environment.MachineName,
                                            "127.0.0.1",
                                            Guid.TryParse(freshlySavedConfig?.DeviceId, out var gid) ? gid : null,
                                            freshlySavedConfig?.DeviceToken
                                        );
                                        _ = Task.Run(async () =>
                                        {
                                            try
                                            {
                                                await PipeProtocol.WriteAsync(client, MessageTypes.RegistrationData, payload, ct);
                                                LogUi("[REGISTRATION_REPLIED] Sent fresh registration data back to Service via pipe");
                                            }
                                            catch (Exception ex)
                                            {
                                                LogUi($"Failed to reply registration data: {ex.Message}");
                                            }
                                        });
                                    }
                                });
                                break;
                            }

                            case MessageTypes.ShowPreComplianceLoading:
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    SurfaceScreenLock();
                                    HeaderTitle.Text = "Pre-compliance check";
                                    HeaderSubtitle.Text = "Verifying running applications against exam policy";
                                    AccentBar.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E5E0D8"));
                                    LoadingPanel.Visibility = Visibility.Visible;
                                    PreComplianceResultPanel.Visibility = Visibility.Collapsed;
                                    StudentVerificationPanel.Visibility = Visibility.Collapsed;
                                    LogUi($"[PRECOMPLIANCE_SHOWN] Screen lock active, pre-compliance loading presented. pid={Environment.ProcessId}");
                                });
                                break;
                            }

                            case MessageTypes.UpdatePreComplianceResult:
                            {
                                var scan = envelope.Payload.Deserialize<PreComplianceScanPayload>();
                                Dispatcher.Invoke(() =>
                                {
                                    LoadingPanel.Visibility = Visibility.Collapsed;
                                    PreComplianceResultPanel.Visibility = Visibility.Visible;
                                    StudentVerificationPanel.Visibility = Visibility.Collapsed;

                                    if (scan != null && scan.IsClean)
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
                                        var count = scan?.SuspiciousProcesses?.Count ?? 0;
                                        StatusBadgeText.Text = $"⚠  {count} unapproved applications detected. Close them before starting the exam.";
                                        SuspiciousProcessList.ItemsSource = scan?.SuspiciousProcesses;
                                        SuspiciousProcessList.Visibility = Visibility.Visible;
                                    }

                                    LogUi($"[PRECOMPLIANCE_SHOWN] UI presented pre-compliance scan results: Clean={scan?.IsClean}");
                                });
                                break;
                            }

                            case MessageTypes.ShowStudentVerification:
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    TransitionToStudentVerification();
                                    LogUi("UI presented in Student Verification state.");
                                });
                                break;
                            }

                            case MessageTypes.SessionStart:
                            case MessageTypes.SessionStop:
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    if (envelope.Type == MessageTypes.SessionStart)
                                    {
                                        LogUi($"[STUDENT_PASSWORD_VERIFIED] Student credentials verified successfully for roll: {_rollNumber}");
                                        LogUi($"[STUDENT_SESSION_ACTIVE] Monitored exam session active for roll: {_rollNumber}");
                                    }
                                    Hide();
                                    LogUi($"UI hidden upon {envelope.Type}.");
                                });
                                break;
                            }
                        }
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    LogUi($"Agent pipe connection error/retry: {ex.Message}");
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                }
                finally
                {
                    if (_activePipeClient != null)
                    {
                        try { await _activePipeClient.DisposeAsync().ConfigureAwait(false); } catch { }
                        _activePipeClient = null;
                    }
                }
            }
        }, ct);
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

    public void SurfaceScreenLock()
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
        if (VerificationErrorBorder != null)
        {
            VerificationErrorBorder.Visibility = Visibility.Collapsed;
        }

        LogUi("[PASSWORD_SCREEN_SHOWN] Candidate verification screen presented with password entry.");

        if (string.IsNullOrWhiteSpace(RollNumberBox.Text))
        {
            RollNumberBox.Text = _rollNumber;
        }
        if (StudentPasswordBox != null)
        {
            StudentPasswordBox.Password = string.Empty;
        }
        UpdateVerifyButtonState();
        if (string.IsNullOrWhiteSpace(RollNumberBox.Text))
        {
            RollNumberBox.Focus();
            RollNumberBox.SelectAll();
        }
        else
        {
            StudentPasswordBox?.Focus();
        }
    }

    public async Task StartActiveMonitoringSessionAsync()
    {
        _rollNumber = RollNumberBox.Text.Trim();
        _sessionId = Guid.NewGuid().ToString("N");

        LogUi($"Starting active monitoring session: sessionId={_sessionId}, roll={_rollNumber}");

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

            // 1b. Validate student roll number and bind to session on backend
            if (response.IsSuccessStatusCode && !string.IsNullOrWhiteSpace(_rollNumber))
            {
                try
                {
                    var verifyReq = new
                    {
                        sessionId = _sessionId,
                        rollNumber = _rollNumber
                    };
                    using var verifyMsg = AgentRequestFactory.CreateJsonPost(
                        "api/v1/sessions/verify-student", verifyReq, _config.DeviceToken);
                    using var verifyResponse = await _http.SendAsync(verifyMsg).ConfigureAwait(true);

                    LogUi(AgentRequestFactory.DescribeOutcome(
                        "api/v1/sessions/verify-student",
                        !string.IsNullOrWhiteSpace(_config.DeviceToken),
                        (int)verifyResponse.StatusCode));
                }
                catch (Exception verifyEx)
                {
                    LogUi($"api/v1/sessions/verify-student failed: {verifyEx.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            // Still non-fatal - monitoring must start even if the server never hears about the
            // session - but no longer silent. The previous `catch { }` is why a 401 here left no
            // trace on the workstation.
            LogUi($"api/v1/sessions/start failed: {ex.Message}");
        }

        // 2. Monitoring is owned continuously by the Windows Service
        LogUi("Session marked as Monitoring; Windows Service background monitors are running continuously.");

        // 3. Hide modal shield so student can take exam in Chrome
        Hide();
    }

    private async void PreComplianceContinueButton_Click(object sender, RoutedEventArgs e)
    {
        TransitionToStudentVerification();
        if (_activePipeClient is not null && _activePipeClient.IsConnected)
        {
            try
            {
                await PipeProtocol.WriteAsync(_activePipeClient, MessageTypes.PreComplianceContinued, new { }, CancellationToken.None).ConfigureAwait(false);
                LogUi("Sent PRE_COMPLIANCE_CONTINUED to Agent Service.");
            }
            catch (Exception ex)
            {
                LogUi($"Failed to send PRE_COMPLIANCE_CONTINUED: {ex.Message}");
            }
        }
    }

    private async void VerifyStudentButton_Click(object sender, RoutedEventArgs e)
    {
        var roll = RollNumber;
        var pwd = StudentPasswordBox?.Password ?? "";
        if (string.IsNullOrWhiteSpace(roll) || string.IsNullOrWhiteSpace(pwd)) return;

        if (pwd.Length < 4)
        {
            if (VerificationErrorBorder != null && VerificationErrorText != null)
            {
                VerificationErrorText.Text = "Password must be at least 4 characters.";
                VerificationErrorBorder.Visibility = Visibility.Visible;
            }
            return;
        }

        if (VerificationErrorBorder != null)
        {
            VerificationErrorBorder.Visibility = Visibility.Collapsed;
        }
        VerifyStudentButton.IsEnabled = false;

        LogUi($"[STUDENT_PASSWORD_SUBMITTED] Roll={roll}");

        if (_activePipeClient is not null && _activePipeClient.IsConnected)
        {
            try
            {
                await PipeProtocol.WriteAsync(_activePipeClient, MessageTypes.StudentVerificationResult, new StudentVerificationPayload(roll, pwd), CancellationToken.None).ConfigureAwait(false);
                LogUi($"Sent STUDENT_VERIFICATION_RESULT ({roll}) to Agent Service.");
            }
            catch (Exception ex)
            {
                LogUi($"Failed to send STUDENT_VERIFICATION_RESULT: {ex.Message}");
                VerifyStudentButton.IsEnabled = true;
            }
        }
        else
        {
            await StartActiveMonitoringSessionAsync();
        }
    }

    private void RollNumberBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        UpdateVerifyButtonState();
    }

    private void StudentPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        UpdateVerifyButtonState();
    }

    private void UpdateVerifyButtonState()
    {
        if (VerifyStudentButton != null && RollNumberBox != null && StudentPasswordBox != null)
        {
            VerifyStudentButton.IsEnabled = !string.IsNullOrWhiteSpace(RollNumberBox.Text) &&
                                            !string.IsNullOrWhiteSpace(StudentPasswordBox.Password);
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _pipeCts?.Cancel();
        if (_activePipeClient != null)
        {
            try { _activePipeClient.Dispose(); } catch { }
            _activePipeClient = null;
        }
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
