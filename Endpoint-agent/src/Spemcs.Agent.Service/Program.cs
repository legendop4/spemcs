using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddProvider(new RollingFileLoggerProvider(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs", "Logs")));
builder.Services.AddWindowsService(options => options.ServiceName = "SPEMCS Endpoint Agent");
var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs");
builder.Services.AddSingleton<IAgentStore>(_ => new SqliteAgentStore(root));
builder.Services.AddSingleton<IUiLauncher, InteractiveSessionUiLauncher>();
builder.Services.AddSingleton<IExamUiGateway, NamedPipeUiGateway>();

// Milestone 4 Network Enforcement & Rollback Infrastructure
builder.Services.AddSingleton<IFirewallAdapter, WindowsFirewallAdapter>();
builder.Services.AddSingleton<IRollbackJournal>(_ => new SqliteRollbackJournal(root));
builder.Services.AddSingleton<INetworkEnforcer, NetworkEnforcer>();

// Milestone 5 Policy Distribution & Pre-Enforcement Verification
builder.Services.AddSingleton<ITrustedKeyStore, TrustedKeyStore>();
builder.Services.AddSingleton<IManagementConnectivityVerifier, ManagementConnectivityVerifier>();
builder.Services.AddSingleton<IPolicyReceiver, PolicyReceiver>();

// Milestone 6 Exam Lifecycle Integration & Enforcement State Machine
builder.Services.AddSingleton<IEnforcementStateMachine, EnforcementStateMachine>();

var backendUrl = builder.Configuration["BackendApiUrl"] ?? "http://127.0.0.1:8000/";
builder.Services.AddHttpClient<IRegistrationService, BackendRegistrationService>(c => c.BaseAddress = new Uri(backendUrl));
builder.Services.AddHttpClient<ISessionService, BackendSessionService>(c => c.BaseAddress = new Uri(backendUrl));
builder.Services.AddHttpClient<IEventPublisher, BackendEventPublisher>(c => c.BaseAddress = new Uri(backendUrl));

builder.Services.AddSingleton<AgentWorker>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentWorker>());
builder.Services.AddHostedService<ControlPipeWorker>();
await builder.Build().RunAsync();
