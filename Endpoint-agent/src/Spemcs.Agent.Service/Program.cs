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

// Resolve backend URL from config.json, appsettings, or default 8002
var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs", "Endpoint Agent", "config.json");
string backendUrl = "http://127.0.0.1:8002/";

// Provisional approved browser, used only until a signed policy binds one (see
// IApprovedBrowserContext). The value is NOT security-relevant on its own - the firewall allowlist
// is scoped from the signed policy - but it decides which browser the monitor treats as approved
// during pre-compliance, so it is read from configuration instead of hardcoded at each call site.
var hostApprovedBrowser = ApprovedBrowserFamily.Chrome;
var approvedBrowserProvenance = "built-in fallback (no 'approvedBrowser' in config.json)";

if (File.Exists(configPath))
{
    try
    {
        using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(configPath));
        if (doc.RootElement.TryGetProperty("serverUrl", out var sProp) && !string.IsNullOrWhiteSpace(sProp.GetString()))
        {
            backendUrl = sProp.GetString()!.TrimEnd('/') + "/";
        }

        if (doc.RootElement.TryGetProperty("approvedBrowser", out var bProp)
            && bProp.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            var configuredBrowser = bProp.GetString();
            if (ApprovedBrowserFamilies.TryParse(configuredBrowser, out var parsedBrowser))
            {
                hostApprovedBrowser = parsedBrowser;
                approvedBrowserProvenance = "config.json 'approvedBrowser'";
            }
            else
            {
                // Deliberately not fatal: an unrecognised value must not stop the agent from
                // starting, because the signed policy overrides this anyway. It is surfaced at
                // startup so a typo ("firefox", "Chromium") is visible rather than silently ignored.
                approvedBrowserProvenance =
                    $"built-in fallback (config.json 'approvedBrowser' = '{configuredBrowser}' is not a supported family)";
            }
        }
    }
    catch { }
}
if (string.IsNullOrWhiteSpace(backendUrl) || backendUrl.Contains(":8000"))
{
    backendUrl = builder.Configuration["BackendApiUrl"] ?? "http://127.0.0.1:8002/";
}
if (!backendUrl.EndsWith("/")) backendUrl += "/";

// Milestone 5 Policy Distribution & Pre-Enforcement Verification
builder.Services.AddSingleton<ITrustedKeyStore, TrustedKeyStore>();
builder.Services.AddSingleton<IManagementConnectivityVerifier>(sp =>
{
    var secMode = backendUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        ? TransportSecurityMode.StrictHttps
        : TransportSecurityMode.AllowInsecureHttpForTesting;
    var hostName = new Uri(backendUrl).Host;
    var mgmtHttp = sp.GetRequiredService<IHttpClientFactory>().CreateClient("BackendApi");
    return new ManagementConnectivityVerifier(
        httpClient: mgmtHttp,
        logger: sp.GetRequiredService<ILogger<ManagementConnectivityVerifier>>(),
        securityMode: secMode,
        expectedHostname: hostName);
});
builder.Services.AddSingleton<IPolicyReceiver, PolicyReceiver>();

// Milestone 6 Exam Lifecycle Integration & Enforcement State Machine
//
// One shared approved-browser context for the whole process. Registered as a singleton on purpose:
// the enforcement state machine WRITES the signed family into it at activation, and the process
// classifier plus the network policy evaluator READ it while monitoring. Two instances would
// reintroduce exactly the split-brain this type exists to prevent (firewall allows msedge.exe while
// the monitor keeps approving chrome.exe).
builder.Services.AddSingleton<IApprovedBrowserContext>(sp =>
{
    var context = new ApprovedBrowserContext(hostApprovedBrowser, approvedBrowserProvenance);
    sp.GetRequiredService<ILogger<ApprovedBrowserContext>>().LogInformation(
        "Provisional approved browser: {Family} from {Provenance}. A signed exam policy overrides this at activation.",
        hostApprovedBrowser, approvedBrowserProvenance);
    return context;
});

builder.Services.AddSingleton<IEnforcementStateMachine, EnforcementStateMachine>();

builder.Services.AddHttpClient("BackendApi", c => c.BaseAddress = new Uri(backendUrl));
builder.Services.AddHttpClient<IRegistrationService, BackendRegistrationService>(c => c.BaseAddress = new Uri(backendUrl));
builder.Services.AddHttpClient<ISessionService, BackendSessionService>(c => c.BaseAddress = new Uri(backendUrl));
builder.Services.AddHttpClient<IEventPublisher, BackendEventPublisher>(c => c.BaseAddress = new Uri(backendUrl));

builder.Services.AddSingleton<AgentWorker>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentWorker>());
builder.Services.AddHostedService<ControlPipeWorker>();
await builder.Build().RunAsync();
