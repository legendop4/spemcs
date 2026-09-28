using System;
using System.Linq;
using System.Threading;
using System.Windows;
using Spemcs.Agent.Ipc;
using Spemcs.Agent.UI.Services;
using Spemcs.Agent.UI.Views;

namespace Spemcs.Agent.UI;

public partial class App : Application
{
    private Mutex? _instanceMutex;
    private bool _hasMutexOwnership;
    private const string MutexName = @"Global\SpemcsEndpointAgentMutex";

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);
    private const int ATTACH_PARENT_PROCESS = -1;

    private static void LogApp(string msg) => Spemcs.Agent.UI.MainWindow.LogUi(msg);

    public App()
    {
        DispatcherUnhandledException += (s, args) =>
        {
            LogApp($"[UI_STARTUP_FAILED] type={args.Exception.GetType().FullName} message={args.Exception.Message} stack={args.Exception.StackTrace}");
        };

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                LogApp($"[UI_STARTUP_FAILED] type={ex.GetType().FullName} message={ex.Message} stack={ex.StackTrace}");
            }
        };

        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, args) =>
        {
            LogApp($"[UI_STARTUP_FAILED] type={args.Exception.GetType().FullName} message={args.Exception.Message} stack={args.Exception.StackTrace}");
        };
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        base.OnStartup(e);

        try
        {
            LogApp($"[UI_PROCESS_START] args='{string.Join(" ", e.Args)}', pid={Environment.ProcessId}, session={System.Diagnostics.Process.GetCurrentProcess().SessionId}");

        // 1. Single-Instance Protection
        try
        {
            _instanceMutex = new Mutex(true, MutexName, out var isOnlyInstance);
            _hasMutexOwnership = isOnlyInstance;
        }
        catch (AbandonedMutexException)
        {
            // The previous instance exited or was terminated without releasing the mutex.
            // When AbandonedMutexException is thrown, mutex ownership is granted to this thread.
            _hasMutexOwnership = true;
        }
        catch (Exception)
        {
            _hasMutexOwnership = false;
        }

        if (_hasMutexOwnership)
        {
            LogApp($"[UI_MUTEX_ACQUIRED] mutexName={MutexName}, pid={Environment.ProcessId}");
        }

        var isExamMode = e.Args.Any(a => string.Equals(a, "--exam-mode", StringComparison.OrdinalIgnoreCase));
        if (!_hasMutexOwnership && isExamMode)
        {
            LogApp($"[EXAM_MODE_TAKEOVER] Mutex currently owned; terminating orphan/idle UI process and claiming mutex for exam mode. pid={Environment.ProcessId}");
            TryKillOrphanUiProcesses();
            try
            {
                _instanceMutex?.Dispose();
                _instanceMutex = new Mutex(true, MutexName, out _hasMutexOwnership);
            }
            catch (AbandonedMutexException)
            {
                _hasMutexOwnership = true;
            }
            catch { }

            for (int retry = 0; retry < 10 && !_hasMutexOwnership; retry++)
            {
                Thread.Sleep(100);
                try
                {
                    _instanceMutex?.Dispose();
                    _instanceMutex = new Mutex(true, MutexName, out _hasMutexOwnership);
                }
                catch (AbandonedMutexException)
                {
                    _hasMutexOwnership = true;
                }
                catch { }
            }

            if (_hasMutexOwnership)
            {
                LogApp($"[UI_MUTEX_ACQUIRED] mutexName={MutexName}, pid={Environment.ProcessId} (after takeover)");
            }
        }

        if (!_hasMutexOwnership && !isExamMode)
        {
            var isSetupRequested = e.Args.Any(a => string.Equals(a, "--setup", StringComparison.OrdinalIgnoreCase));
            var configCheck = new AgentConfigService().Load();
            bool isAlreadyEnrolled = configCheck != null && configCheck.IsEnrolled && configCheck.IsValid();

            LogApp($"[ENROLLMENT_STATE_EVALUATED] instance=SECONDARY, enrolled={isAlreadyEnrolled}, hasDeviceId={!string.IsNullOrWhiteSpace(configCheck?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(configCheck?.DeviceToken)}, configPath={new AgentConfigService().ConfigFilePath}, pid={Environment.ProcessId}");

            // Setup is strictly suppressed if already enrolled!
            if (!isAlreadyEnrolled)
            {
                LogApp($"[UI_SETUP_REQUESTED] instance=SECONDARY, reason=UNENROLLED, pid={Environment.ProcessId}");
                // Try to forward setup request to the already running UI instance
                bool forwarded = TrySignalExistingUiForSetup();
                if (forwarded)
                {
                    Shutdown(0);
                    return;
                }

                // If forwarding failed (e.g. existing instance is frozen or an orphaned process in Session 0),
                // terminate the zombie UI process, claim mutex, and proceed to show SetupWizardWindow
                TryKillOrphanUiProcesses();
                try
                {
                    _instanceMutex?.Dispose();
                    _instanceMutex = new Mutex(true, MutexName, out _hasMutexOwnership);
                }
                catch (AbandonedMutexException)
                {
                    _hasMutexOwnership = true;
                }
                catch { }
            }
            else
            {
                LogApp($"[UI_SETUP_SUPPRESSED] instance=SECONDARY, reason=ALREADY_ENROLLED, setupRequested={isSetupRequested}, enrolled=true, hasDeviceId={!string.IsNullOrWhiteSpace(configCheck?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(configCheck?.DeviceToken)}, pid={Environment.ProcessId}");
                try
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    Console.WriteLine("[SPEMCS] An instance of SPEMCS Endpoint Agent is already running and enrolled. Exiting duplicate instance.");
                }
                catch { }

                Shutdown(0);
                return;
            }
        }

        var configService = new AgentConfigService();
        var isSetupFlag = e.Args.Any(a => string.Equals(a, "--setup", StringComparison.OrdinalIgnoreCase));
        var config = configService.Load();
        bool enrolled = config != null && config.IsEnrolled && config.IsValid();

        LogApp($"[ENROLLMENT_STATE_EVALUATED] instance=PRIMARY, enrolled={enrolled}, hasDeviceId={!string.IsNullOrWhiteSpace(config?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(config?.DeviceToken)}, configPath={configService.ConfigFilePath}, pid={Environment.ProcessId}");

        // 2. Setup Wizard if not enrolled (even if --setup is requested, do NOT show if already enrolled)
        // Under --exam-mode, the agent service is driving the exam lifecycle: do NOT block on Setup Wizard!
        if (!enrolled && !isExamMode)
        {
            LogApp($"[UI_SETUP_WINDOW_SHOWN] instance=PRIMARY, reason=UNENROLLED, enrolled=false, hasDeviceId={!string.IsNullOrWhiteSpace(config?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(config?.DeviceToken)}, configPath={configService.ConfigFilePath}, pid={Environment.ProcessId}");
            var wizard = new SetupWizardWindow();
            var result = wizard.ShowDialog();

            if (result != true)
            {
                // User cancelled setup without registering
                Shutdown(0);
                return;
            }

            // Reload freshly saved config
            config = configService.Load();
            enrolled = config != null && config.IsEnrolled && config.IsValid();
            LogApp($"[ENROLLMENT_STATE_EVALUATED] instance=PRIMARY_POST_SETUP, enrolled={enrolled}, hasDeviceId={!string.IsNullOrWhiteSpace(config?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(config?.DeviceToken)}, configPath={configService.ConfigFilePath}, pid={Environment.ProcessId}");
        }
        else if (isExamMode && !enrolled)
        {
            LogApp($"[EXAM_MODE_BYPASS_ENROLLMENT_WIZARD] instance=PRIMARY, isExamMode=true, enrolled={enrolled}; bypassing SetupWizard to surface exam lock screen and connect to Service pipe.");
        }
        else if (isSetupFlag)
        {
            LogApp($"[UI_SETUP_SUPPRESSED] instance=PRIMARY, reason=ALREADY_ENROLLED, setupRequested=true, enrolled=true, hasDeviceId={!string.IsNullOrWhiteSpace(config?.DeviceId)}, hasToken={!string.IsNullOrWhiteSpace(config?.DeviceToken)}, pid={Environment.ProcessId}");
        }

        // 3. Launch Silent Background Agent
        var mainWindow = new MainWindow(config);
        MainWindow = mainWindow;
        LogApp($"[UI_APP_INITIALIZED] pid={Environment.ProcessId}");
        if (isExamMode)
        {
            mainWindow.SurfaceScreenLock();
        }
        }
        catch (Exception ex)
        {
            LogApp($"[UI_STARTUP_FAILED] type={ex.GetType().FullName} message={ex.Message} stack={ex.StackTrace}");
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_hasMutexOwnership && _instanceMutex != null)
        {
            try
            {
                _instanceMutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // Mutex was not owned by the calling thread
            }
            finally
            {
                _hasMutexOwnership = false;
            }
        }

        _instanceMutex?.Dispose();
        _instanceMutex = null;

        base.OnExit(e);
    }

    private static bool TrySignalExistingUiForSetup()
    {
        try
        {
            using var client = new System.IO.Pipes.NamedPipeClientStream(".", PipeNames.UiSetup, System.IO.Pipes.PipeDirection.Out);
            client.Connect(1500);
            using var writer = new System.IO.StreamWriter(client, System.Text.Encoding.UTF8);
            writer.WriteLine("SHOW_SETUP");
            writer.Flush();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void TryKillOrphanUiProcesses()
    {
        try
        {
            var currentPid = Environment.ProcessId;
            foreach (var proc in System.Diagnostics.Process.GetProcessesByName("Spemcs.Agent.UI"))
            {
                if (proc.Id != currentPid)
                {
                    try { proc.Kill(); proc.WaitForExit(1000); } catch { }
                }
            }
        }
        catch { }
    }
}
