using System;
using System.Linq;
using System.Threading;
using System.Windows;
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

    protected override void OnStartup(StartupEventArgs e)
    {
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        base.OnStartup(e);

        // 1. Single-Instance Protection
        try
        {
            _instanceMutex = new Mutex(true, MutexName, out var isOnlyInstance);
            _hasMutexOwnership = isOnlyInstance;
        }
        catch (Exception)
        {
            _hasMutexOwnership = false;
        }

        if (!_hasMutexOwnership)
        {
            // If already running and not explicit setup, notify and exit cleanly
            var isSetupRequested = e.Args.Any(a => string.Equals(a, "--setup", StringComparison.OrdinalIgnoreCase));
            if (!isSetupRequested)
            {
                try
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                    Console.WriteLine("[SPEMCS] An instance of SPEMCS Endpoint Agent is already running. Exiting duplicate instance.");
                }
                catch { }

                Shutdown(0);
                return;
            }
        }

        var configService = new AgentConfigService();
        var isSetupFlag = e.Args.Any(a => string.Equals(a, "--setup", StringComparison.OrdinalIgnoreCase));
        var config = configService.Load();

        // 2. Setup Wizard if not registered or --setup requested
        if (isSetupFlag || config == null || !config.Registered || !config.IsValid())
        {
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
        }

        // 3. Launch Silent Background Agent
        var mainWindow = new MainWindow(config);
        MainWindow = mainWindow;
        // Window stays hidden until WebSocket receives LAUNCH_EXAM_MODE!
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
}
