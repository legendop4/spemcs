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
    private const string MutexName = @"Global\SpemcsEndpointAgentMutex";

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 1. Single-Instance Protection
        _instanceMutex = new Mutex(true, MutexName, out var isOnlyInstance);
        if (!isOnlyInstance)
        {
            // If already running and not explicit setup, exit cleanly
            var isSetupRequested = e.Args.Any(a => string.Equals(a, "--setup", StringComparison.OrdinalIgnoreCase));
            if (!isSetupRequested)
            {
                Shutdown(0);
                return;
            }
        }

        ShutdownMode = ShutdownMode.OnExplicitShutdown;

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
        _instanceMutex?.ReleaseMutex();
        _instanceMutex?.Dispose();
        base.OnExit(e);
    }
}
