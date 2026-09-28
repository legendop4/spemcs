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
var configPathEarly = Path.Combine(root, "Endpoint Agent", "config.json");

// Eradicate previous stale registration databases if fresh/un-enrolled
try
{
    bool isStaleOrUnenrolled = false;
    if (File.Exists(configPathEarly))
    {
        using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(configPathEarly));
        var rootElem = doc.RootElement;

        bool hasRegistered = rootElem.TryGetProperty("registered", out var regProp) &&
            (regProp.ValueKind == System.Text.Json.JsonValueKind.True ||
             (regProp.ValueKind == System.Text.Json.JsonValueKind.String && bool.TryParse(regProp.GetString(), out var rb) && rb));

        bool hasDeviceId = rootElem.TryGetProperty("deviceId", out var idProp) &&
            !string.IsNullOrWhiteSpace(idProp.GetString()) &&
            Guid.TryParse(idProp.GetString(), out var devIdGuid) && devIdGuid != Guid.Empty;

        bool hasDeviceToken = rootElem.TryGetProperty("deviceToken", out var tokProp) &&
            !string.IsNullOrWhiteSpace(tokProp.GetString());

        if (!hasRegistered || (!hasDeviceId && !hasDeviceToken))
        {
            isStaleOrUnenrolled = true;
        }
    }
    else
    {
        isStaleOrUnenrolled = true;
    }

    if (isStaleOrUnenrolled)
    {
        var dbFile = Path.Combine(root, "agent.db");
        if (File.Exists(dbFile)) File.Delete(dbFile);
        if (File.Exists(dbFile + "-shm")) File.Delete(dbFile + "-shm");
        if (File.Exists(dbFile + "-wal")) File.Delete(dbFile + "-wal");
        var jFile = Path.Combine(root, "network_journal.db");
        if (File.Exists(jFile)) File.Delete(jFile);
    }
}
catch { }

builder.Services.AddSingleton<IAgentStore>(_ => new SqliteAgentStore(root));
builder.Services.AddSingleton<IUiLauncher, InteractiveSessionUiLauncher>();
builder.Services.AddSingleton<IExamUiGateway, NamedPipeUiGateway>();

// Milestone 4 Network Enforcement & Rollback Infrastructure
builder.Services.AddSingleton<IFirewallAdapter, WindowsFirewallAdapter>();
builder.Services.AddSingleton<IRollbackJournal>(_ => new SqliteRollbackJournal(root));
builder.Services.AddSingleton<INetworkEnforcer, NetworkEnforcer>();

// Resolve backend URL with strict priority: config.json > env var > appsettings > compiled default.
// See ServiceConfigResolver for the precedence documentation and the :8000 bug this replaced.
var configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Spemcs", "Endpoint Agent", "config.json");
string? configJsonServerUrl = null;

// Provisional approved browser, used only until a signed policy binds one (see
// IApprovedBrowserContext). The value is NOT security-relevant on its own - the firewall allowlist
// is scoped from the signed policy - but it decides which browser the monitor treats as approved
// during pre-compliance, so it is read from configuration instead of hardcoded at each call site.
var hostApprovedBrowser = ApprovedBrowserFamily.Chrome;
var approvedBrowserProvenance = "built-in fallback (no 'approvedBrowser' in config.json)";

// Bootstrap enrolment key. It authorises this machine to register and thereby to obtain the
// device token every other agent call is authenticated with, so it is a real shared secret and is
// read from configuration only - config.json, then the SPEMCS_ENROLLMENT_KEY environment
// variable, then host configuration. There is deliberately NO compiled-in default: a key baked
// into a binary installed on every examination workstation is readable by anyone holding the
// binary. Null here means unconfigured, which surfaces as a 401 from registration naming the
// problem, rather than as a working default nobody replaces.
string? enrollmentKey = null;
string? initialDeviceToken = null;

if (File.Exists(configPath))
{
    try
    {
        using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(configPath));
        if (doc.RootElement.TryGetProperty("serverUrl", out var sProp) && !string.IsNullOrWhiteSpace(sProp.GetString()))
        {
            configJsonServerUrl = sProp.GetString();
        }

        if (doc.RootElement.TryGetProperty("enrollmentKey", out var eProp)
            && eProp.ValueKind == System.Text.Json.JsonValueKind.String
            && !string.IsNullOrWhiteSpace(eProp.GetString()))
        {
            enrollmentKey = eProp.GetString();
        }

        bool isReg = doc.RootElement.TryGetProperty("registered", out var regP) &&
            (regP.ValueKind == System.Text.Json.JsonValueKind.True ||
             (regP.ValueKind == System.Text.Json.JsonValueKind.String && bool.TryParse(regP.GetString(), out var rb) && rb));

        bool hasValidId = doc.RootElement.TryGetProperty("deviceId", out var idP) &&
            Guid.TryParse(idP.GetString(), out var gid) && gid != Guid.Empty;

        if (isReg && hasValidId && doc.RootElement.TryGetProperty("deviceToken", out var dtProp)
            && dtProp.ValueKind == System.Text.Json.JsonValueKind.String
            && !string.IsNullOrWhiteSpace(dtProp.GetString()))
        {
            initialDeviceToken = dtProp.GetString();
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

var resolved = ServiceConfigResolver.Resolve(
    configJsonServerUrl: configJsonServerUrl,
    environmentUrl: Environment.GetEnvironmentVariable("SPEMCS_BACKEND_URL"),
    appsettingsUrl: builder.Configuration["BackendApiUrl"]);
var backendUrl = resolved.ResolvedUrl;

if (string.IsNullOrWhiteSpace(enrollmentKey))
{
    enrollmentKey = Environment.GetEnvironmentVariable("SPEMCS_ENROLLMENT_KEY")
                    ?? builder.Configuration["EnrollmentKey"];
}

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

// One credential store for the whole process. Registration writes the device token into it and
// the session and event adapters read it, so this MUST be a singleton: three separate instances
// would mean registration credentials that no other call can see.
builder.Services.AddSingleton(_ => new DeviceCredentialStore(enrollmentKey, initialDeviceToken));

builder.Services.AddTransient(_ => new DynamicBackendAddressHandler(initialBackendUrl: backendUrl));

builder.Services.AddHttpClient("BackendApi", c => c.BaseAddress = new Uri(backendUrl))
    .AddHttpMessageHandler<DynamicBackendAddressHandler>();
builder.Services.AddHttpClient<IRegistrationService, BackendRegistrationService>(c => c.BaseAddress = new Uri(backendUrl))
    .AddHttpMessageHandler<DynamicBackendAddressHandler>();
builder.Services.AddHttpClient<ISessionService, BackendSessionService>(c => c.BaseAddress = new Uri(backendUrl))
    .AddHttpMessageHandler<DynamicBackendAddressHandler>();
builder.Services.AddHttpClient<IEventPublisher, BackendEventPublisher>(c => c.BaseAddress = new Uri(backendUrl))
    .AddHttpMessageHandler<DynamicBackendAddressHandler>();

builder.Services.AddSingleton(resolved);
builder.Services.AddSingleton<IKeyringSyncService, KeyringSyncService>();
builder.Services.AddSingleton<IExamLifecycleCoordinator, ExamLifecycleCoordinator>();
builder.Services.AddSingleton<IRegistrationSynchronizer, RegistrationSynchronizer>();

builder.Services.AddSingleton<CentralWebSocketWorker>();
builder.Services.AddSingleton<IWebSocketStatusProvider>(sp => sp.GetRequiredService<CentralWebSocketWorker>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<CentralWebSocketWorker>());
builder.Services.AddSingleton<AgentWorker>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentWorker>());
builder.Services.AddHostedService<ControlPipeWorker>();
var host = builder.Build();
var startupLogger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Spemcs.Agent.Service.Startup");
resolved.LogResolution(startupLogger);
await host.RunAsync();
