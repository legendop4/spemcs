using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Text;

namespace Spemcs.Agent.Core;

// ── 1. WindowsProcessSource ──────────────────────────────────────────────
public sealed class WindowsProcessSource : IProcessSource
{
    public IReadOnlyList<ProcessInfo> GetProcesses()
    {
        var parents = ReadParentMap(); 
        return Process.GetProcesses().Select(p => ToInfo(p, parents.TryGetValue(p.Id, out var parent) ? parent : null)).ToArray();
    }
    
    public ProcessInfo? FindById(int processId) 
    { 
        try 
        { 
            var parents = ReadParentMap(); 
            return ToInfo(Process.GetProcessById(processId), parents.TryGetValue(processId, out var parent) ? parent : null); 
        } 
        catch { return null; } 
    }
    
    private static ProcessInfo ToInfo(Process p, int? parentProcessId)
    {
        try 
        { 
            string name = "unknown";
            try { name = p.ProcessName; } catch { }
            string? path = TryGetProcessPath(p);
            bool hasWindow = false;
            try { hasWindow = p.MainWindowHandle != IntPtr.Zero; } catch { }
            return new ProcessInfo(p.Id, name, path, parentProcessId, hasWindow); 
        }
        catch 
        { 
            return new ProcessInfo(p.Id, "unknown", null, parentProcessId, false); 
        }
        finally { try { p.Dispose(); } catch { } }
    }

    private static string? TryGetProcessPath(Process p)
    {
        try
        {
            if (p.MainModule?.FileName is string mainPath && !string.IsNullOrWhiteSpace(mainPath))
                return mainPath;
        }
        catch { }

        // Fallback: QueryFullProcessImageName for elevated/background processes
        try
        {
            var handle = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, (uint)p.Id);
            if (handle != IntPtr.Zero)
            {
                try
                {
                    var buffer = new StringBuilder(1024);
                    int size = buffer.Capacity;
                    if (QueryFullProcessImageName(handle, 0, buffer, ref size))
                    {
                        return buffer.ToString();
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
        }
        catch { }

        return null;
    }
    
    private static Dictionary<int, int> ReadParentMap()
    {
        var result = new Dictionary<int, int>(); 
        var snapshot = CreateToolhelp32Snapshot(0x00000002, 0); 
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return result;
        
        try 
        { 
            var entry = new ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<ProcessEntry32>() }; 
            if (!Process32First(snapshot, ref entry)) return result; 
            do { result[(int)entry.th32ProcessID] = (int)entry.th32ParentProcessID; } while (Process32Next(snapshot, ref entry)); 
            return result; 
        }
        finally { CloseHandle(snapshot); }
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] 
    private struct ProcessEntry32 
    { 
        public uint dwSize, cntUsage, th32ProcessID, th32DefaultHeapID, th32ModuleID, cntThreads, th32ParentProcessID, pcPriClassBase, dwFlags; 
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile; 
    }
    
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder text, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
}

// ── 2. Windows-Aware Process & Service Classifier ───────────────────────
public sealed class ConfigurableProcessClassifier : IProcessClassifier
{
    private readonly string _selfRoot;
    private readonly string _windowsRoot;
    private readonly IFileTrustVerifier _trust;
    private readonly Func<int, ProcessInfo?>? _parentResolver;
    // Read live, not captured at construction: the approved family is only authoritative once a
    // signed policy has bound it, which happens after this classifier is built (P0-E).
    private readonly IApprovedBrowserContext _approvedBrowser;
    // Thread-safe: the classifier instance is shared between PreComplianceEngine and the
    // ProcessMonitor reconciliation loop, which can run concurrently (P0-A).
    private readonly ConcurrentDictionary<(string Path, string Hash), FileTrustResult> _cache = new();

    // Core Windows System processes that may run without accessible executable paths or visible windows
    private static readonly HashSet<string> EssentialSystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Secure System", "Memory Compression", "Interrupts",
        "smss", "csrss", "wininit", "services", "lsass", "LsaIso", "svchost", "fontdrvhost",
        "WUDFHost", "dwm", "sihost", "taskhostw", "explorer", "spoolsv", "ctfmon",
        "SearchIndexer", "SecurityHealthService", "MsMpEng", "MpDefenderCoreService",
        "NisSrv", "NgcIso", "smartscreen", "ApplicationFrameHost", "SystemSettings",
        "audiodg", "dasHost", "dllhost", "RuntimeBroker", "SearchHost", "StartMenuExperienceHost",
        "ShellExperienceHost", "conhost", "cmd", "wlanext", "svchost.exe"
    };

    private static readonly HashSet<string> KnownUnapprovedBrowserExes = new(StringComparer.OrdinalIgnoreCase)
    {
        "firefox.exe", "opera.exe", "brave.exe", "vivaldi.exe",
        "iexplore.exe", "safari.exe", "waterfox.exe", "tor.exe", "firefox",
        "opera", "brave", "vivaldi", "tor"
    };

    private static readonly HashSet<string> KnownForbiddenProctoringApps = new(StringComparer.OrdinalIgnoreCase)
    {
        // Remote Access / Background Control Tools
        "dwagent.exe", "dwagent", "dwagsvc.exe", "dwagsvc", "dwrcs.exe", "dwrcs", "dwservice.exe", "dwservice",
        "anydesk.exe", "anydesk", "teamviewer.exe", "teamviewer", "teamviewer_service.exe", "teamviewer_service",
        "rustdesk.exe", "rustdesk", "ultraviewer.exe", "ultraviewer", "parsec.exe", "parsec",
        "splashtop.exe", "splashtop", "ammyy.exe", "ammyy", "supremo.exe", "supremo", "logmein.exe", "logmein",
        "vncviewer.exe", "vncviewer", "winvnc.exe", "winvnc", "tightvnc.exe", "tightvnc", "tvnserver.exe", "tvnserver",
        "realvnc.exe", "realvnc", "screenconnect.client.exe", "screenconnect.client", "screenconnect.service.exe", "screenconnect.service",
        "connectwise.exe", "connectwise", "quickassist.exe", "quickassist", "mstsc.exe", "mstsc", "remotedesktop.exe", "remotedesktop",
        "ngrok.exe", "ngrok",

        // AI Assistants & Communication Apps
        "chatgpt.exe", "chatgpt", "chatgpt classic.exe", "chatgpt classic", "claude.exe", "claude",
        "codex.exe", "codex", "copilot.exe", "copilot", "gemini.exe", "gemini",
        "discord.exe", "discord", "slack.exe", "slack", "telegram.exe", "telegram",
        "whatsapp.exe", "whatsapp", "signal.exe", "signal", "teams.exe", "teams",
        "skype.exe", "skype", "zoom.exe", "zoom",

        // Screen Capture, Notes & Cheating Tools
        "spotify.exe", "spotify", "obs64.exe", "obs64", "obs32.exe", "obs32", "vlc.exe", "vlc",
        "code.exe", "code", "idea64.exe", "idea64", "pycharm64.exe", "pycharm64", "devenv.exe", "devenv",
        "notepad.exe", "notepad", "notepad++.exe", "notepad++", "calc.exe", "calc", "CalculatorApp.exe", "CalculatorApp",
        "taskmgr.exe", "taskmgr", "powershell.exe", "powershell", "pwsh.exe", "pwsh", "WindowsTerminal.exe", "WindowsTerminal",
        "cheatengine.exe", "cheatengine", "cheatengine-x86_64.exe", "cheatengine-x86_64",
        "x64dbg.exe", "x64dbg", "x32dbg.exe", "x32dbg", "processhacker.exe", "processhacker", "wireshark.exe", "wireshark"
    };

    // Substring / prefix keywords that immediately trigger Suspicious classification
    private static readonly string[] ForbiddenKeywords =
    [
        "dwagent", "dwagsvc", "dwrcs", "chatgpt", "claude", "codex", "anydesk",
        "teamviewer", "rustdesk", "ultraviewer", "parsec", "splashtop", "ammyy",
        "supremo", "logmein", "tightvnc", "realvnc", "screenconnect", "connectwise",
        "cheatengine", "discord", "telegram", "whatsapp", "slack", "wireshark", "processhacker"
    ];

    private static readonly HashSet<string> ChromeChildExes = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "crashpad_handler.exe", "elevation_service.exe", "nacl64.exe", "notification_helper.exe"
    };

    private static readonly HashSet<string> EdgeChildExes = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge.exe", "crashpad_handler.exe", "elevation_service.exe", "identity_helper.exe", "notification_helper.exe", "msedgewebview2.exe", "pwahelper.exe"
    };

    /// <summary>
    /// Primary constructor. Takes the shared <see cref="IApprovedBrowserContext"/> rather than a
    /// bare family so that the browser named in the SIGNED policy governs classification, not a
    /// value captured when the service happened to start up.
    /// </summary>
    /// <param name="approvedBrowser">
    /// Required, and deliberately without a default. The previous signature defaulted to
    /// <see cref="ApprovedBrowserFamily.Chrome"/>, which meant an Edge exam produced a classifier
    /// and a firewall that disagreed: msedge.exe was granted network access but reported as an
    /// unapproved browser, while chrome.exe was classified Allowed with no route out.
    /// </param>
    /// <param name="windowsRoot">
    /// Override for the Windows directory used by the trusted-system-path rule. Previously accepted
    /// and then silently discarded, which made the tests that pass a fake root assert nothing.
    /// </param>
    public ConfigurableProcessClassifier(
        IApprovedBrowserContext approvedBrowser,
        string? selfRoot = null,
        IFileTrustVerifier? trust = null,
        Func<int, ProcessInfo?>? parentResolver = null,
        string? windowsRoot = null)
    {
        _approvedBrowser = approvedBrowser ?? throw new ArgumentNullException(nameof(approvedBrowser));
        _selfRoot = Path.GetFullPath(selfRoot ?? AppContext.BaseDirectory);
        _windowsRoot = windowsRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _trust = trust ?? new AuthenticodeTrustVerifier();
        _parentResolver = parentResolver;
    }

    /// <summary>
    /// Convenience overload for hosts and tests that pin one family for the classifier's whole
    /// lifetime. Still required to name the family explicitly.
    /// </summary>
    public ConfigurableProcessClassifier(
        ApprovedBrowserFamily approvedFamily,
        string? selfRoot = null,
        IFileTrustVerifier? trust = null,
        Func<int, ProcessInfo?>? parentResolver = null,
        string? windowsRoot = null)
        : this(ApprovedBrowserContext.ForFamily(approvedFamily), selfRoot, trust, parentResolver, windowsRoot)
    {
    }

    /// <summary>
    /// Classifies one process. The approved family is sampled ONCE here and threaded through the
    /// parent-ancestry recursion, so a policy binding that lands mid-classification cannot produce
    /// a decision where a child was judged against a different browser than its parent.
    /// </summary>
    public ClassificationResult Classify(ProcessInfo process)
        => ClassifyInternal(process, new HashSet<int>(), _approvedBrowser.Effective);

    private ClassificationResult ClassifyInternal(
        ProcessInfo process, HashSet<int> ancestry, ApprovedBrowserFamily approvedFamily)
    {
        // 1. Core Windows Kernel / System pseudo-processes by PID
        if (process.ProcessId <= 4 || string.Equals(process.Name, "Idle", StringComparison.OrdinalIgnoreCase) || string.Equals(process.Name, "System", StringComparison.OrdinalIgnoreCase))
            return new ClassificationResult(Classification.Allowed, "windows-kernel-system", "Windows Infrastructure", "Microsoft Corporation", null, "Essential Windows Kernel System Process");

        string procName = process.Name ?? "unknown";
        string procNameWithExe = procName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? procName : procName + ".exe";

        // 2. Keyword / Explicit Prohibited Apps check (Catches background tools like dwagent, dwagsvc, chatgpt even without path)
        foreach (var keyword in ForbiddenKeywords)
        {
            if (procName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return new ClassificationResult(Classification.Suspicious, "prohibited-keyword-detected", "Prohibited Background Tool", null, null, $"Prohibited tool or service detected ({procName})");
            }
        }

        if (KnownForbiddenProctoringApps.Contains(procName) || KnownForbiddenProctoringApps.Contains(procNameWithExe))
        {
            return new ClassificationResult(Classification.Suspicious, "unapproved-application", "Prohibited Application", null, null, $"Prohibited application running ({procName})");
        }

        if (KnownUnapprovedBrowserExes.Contains(procName) || KnownUnapprovedBrowserExes.Contains(procNameWithExe))
        {
            return new ClassificationResult(Classification.Suspicious, "unapproved-browser", "Unapproved Browser", null, null, $"Unapproved browser ({procName})");
        }

        var path = process.ExecutablePath;

        // 3. Unresolved path check
        if (path is null)
        {
            if (EssentialSystemProcessNames.Contains(procName))
                return new ClassificationResult(Classification.Allowed, "windows-essential-system-name", "Windows Infrastructure", "Microsoft Corporation", null, "Essential Windows System Infrastructure");

            if (!process.HasVisibleWindow)
                return new ClassificationResult(Classification.Allowed, "background-process", "Background Process", null, null, "Background service");

            return new ClassificationResult(Classification.Suspicious, "unresolved-path", "Unknown Application", null, null, $"Unresolved application process ({procName})");
        }

        var full = Path.GetFullPath(path);
        var fileName = Path.GetFileName(full);
        var hash = Hash(full);
        var trust = GetTrust(full, hash);

        // 4. SPEMCS Endpoint Agent components
        if (full.StartsWith(_selfRoot, StringComparison.OrdinalIgnoreCase))
            return new ClassificationResult(Classification.Allowed, "spemcs-component", "SPEMCS Security Agent", trust.Publisher ?? "SPEMCS", hash, "SPEMCS Agent Component");

        // 5. Approved Browser: ONLY the family configured for this exam (approved_browser).
        //    A correctly installed, correctly signed browser of a DIFFERENT family is still
        //    an unapproved browser - the exam configuration is what grants approval.
        bool isChromeExe = string.Equals(fileName, "chrome.exe", StringComparison.OrdinalIgnoreCase);
        bool inChromeDir = full.Contains(@"Google\Chrome\Application", StringComparison.OrdinalIgnoreCase);
        bool isGooglePublisher = trust.Publisher != null && trust.Publisher.Contains("Google", StringComparison.OrdinalIgnoreCase);

        bool isEdgeExe = string.Equals(fileName, "msedge.exe", StringComparison.OrdinalIgnoreCase);
        bool inEdgeDir = full.Contains(@"Microsoft\Edge\Application", StringComparison.OrdinalIgnoreCase);
        bool isMicrosoftPublisher = trust.Publisher != null && trust.Publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

        bool chromeIsApprovedFamily = approvedFamily == ApprovedBrowserFamily.Chrome;
        bool edgeIsApprovedFamily = approvedFamily == ApprovedBrowserFamily.Edge;

        if (chromeIsApprovedFamily)
        {
            if (isChromeExe && inChromeDir && isGooglePublisher)
                return new ClassificationResult(Classification.Allowed, "approved-chrome-browser", "Approved Examination Browser", trust.Publisher, hash, "Google Chrome (Approved Exam Browser)");

            // Chrome helper / child processes
            if (inChromeDir && ChromeChildExes.Contains(fileName) && isGooglePublisher)
                return new ClassificationResult(Classification.Allowed, "approved-chrome-child", "Approved Browser Helper", trust.Publisher, hash, "Google Chrome Helper Process");
        }

        if (edgeIsApprovedFamily)
        {
            if (isEdgeExe && inEdgeDir && isMicrosoftPublisher)
                return new ClassificationResult(Classification.Allowed, "approved-edge-browser", "Approved Examination Browser", trust.Publisher, hash, "Microsoft Edge (Approved Exam Browser)");

            // Edge helper / child processes
            if (inEdgeDir && EdgeChildExes.Contains(fileName) && isMicrosoftPublisher)
                return new ClassificationResult(Classification.Allowed, "approved-edge-child", "Approved Browser Helper", trust.Publisher, hash, "Microsoft Edge Helper Process");
        }

        // Parent context check for approved browser child processes.
        // Only the configured family's browser can confer approval on its children; the
        // parent rule names below are produced exclusively by the family-gated branches above.
        if (process.ParentProcessId is int parentId && _parentResolver is not null && ancestry.Add(process.ProcessId))
        {
            var parent = _parentResolver(parentId);
            if (parent is not null)
            {
                var parentResult = ClassifyInternal(parent, ancestry, approvedFamily);
                if (parentResult.Classification == Classification.Allowed &&
                    ((chromeIsApprovedFamily && string.Equals(parentResult.Rule, "approved-chrome-browser", StringComparison.OrdinalIgnoreCase)) ||
                     (edgeIsApprovedFamily && string.Equals(parentResult.Rule, "approved-edge-browser", StringComparison.OrdinalIgnoreCase))))
                {
                    return new ClassificationResult(Classification.Allowed, "approved-browser-child-inherited", "Approved Browser Helper", trust.Publisher, hash, "Child process of Approved Browser");
                }
            }
        }

        // 6. Explicitly forbidden applications or unapproved browsers by full executable file name.
        //    Any Chrome/Edge binary that did not match an approved branch above lands here -
        //    either because it failed the path/publisher check, or because its family is not
        //    the configured approved_browser for this exam.
        if (KnownUnapprovedBrowserExes.Contains(fileName) || isChromeExe || isEdgeExe)
            return new ClassificationResult(Classification.Suspicious, "unapproved-browser", "Unapproved Browser", trust.Publisher, hash, $"Unapproved Browser ({fileName})");

        if (KnownForbiddenProctoringApps.Contains(fileName))
            return new ClassificationResult(Classification.Suspicious, "unapproved-application", "Prohibited Application", trust.Publisher, hash, $"Prohibited application ({procName})");

        // 7. Essential Windows System Directory & Signed Microsoft Binaries
        if (EssentialSystemProcessNames.Contains(procName) || EssentialSystemProcessNames.Contains(Path.GetFileNameWithoutExtension(fileName)))
        {
            return new ClassificationResult(Classification.Allowed, "windows-essential-service", "Windows Infrastructure", trust.Publisher ?? "Microsoft Corporation", hash, "Essential Windows Service");
        }

        if (!string.IsNullOrEmpty(_windowsRoot) && full.StartsWith(_windowsRoot, StringComparison.OrdinalIgnoreCase) && (trust.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true || !process.HasVisibleWindow))
        {
            return new ClassificationResult(Classification.Allowed, "windows-system-path", "Windows Infrastructure", trust.Publisher ?? "Microsoft Corporation", hash, "Essential Windows System Infrastructure");
        }

        // 8. Everything else in user space is Suspicious
        return new ClassificationResult(Classification.Suspicious, trust.IsTrusted ? "unapproved-application" : "unsigned-application", "Unauthorized Application", trust.Publisher, hash, $"Unauthorized application running ({procName})");
    }

    private string? Hash(string path)
    {
        try { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
        catch { return null; }
    }

    private FileTrustResult GetTrust(string path, string? hash)
    {
        if (hash is null) return new FileTrustResult(false, null, "hash-unavailable");
        var key = (path, hash);

        // GetOrAdd keeps the original semantics exactly: a successful verification is cached
        // for the (path, hash) pair, and a throwing verifier caches nothing and propagates.
        // Under contention the factory may run more than once for the same key, which is
        // benign here - Verify is pure and the duplicate cost is one extra Authenticode check.
        return _cache.GetOrAdd(key, static (k, trust) => trust.Verify(k.Path), _trust);
    }
}

// ── 3. AuthenticodeTrustVerifier ─────────────────────────────────────────
public sealed record FileTrustResult(bool IsTrusted, string? Publisher, string Reason);
public interface IFileTrustVerifier { FileTrustResult Verify(string path); }

public sealed class AuthenticodeTrustVerifier : IFileTrustVerifier
{
    public FileTrustResult Verify(string path)
    {
        try
        {
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;
            var valid = chain.Build(certificate);
            return new FileTrustResult(valid, certificate.GetNameInfo(X509NameType.SimpleName, false), valid ? "authenticode-chain-valid" : "authenticode-chain-invalid");
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        { return new FileTrustResult(false, null, "unsigned-or-unreadable"); }
    }
}

// ── 4. Pre-Compliance Engine (Warning Only) ──────────────────────────────
public sealed class PreComplianceEngine
{
    private readonly IProcessSource _source;
    private readonly IProcessClassifier _classifier;

    public PreComplianceEngine(IProcessSource source, IProcessClassifier classifier)
    {
        _source = source;
        _classifier = classifier;
    }

    public PreComplianceScanResult Scan()
    {
        var processes = _source.GetProcesses();
        var suspicious = new List<ProcessDisplayInfo>();

        foreach (var p in processes)
        {
            var classification = _classifier.Classify(p);
            if (classification.IsSuspicious)
            {
                suspicious.Add(new ProcessDisplayInfo(
                    p.Name,
                    p.ExecutablePath,
                    classification.Category ?? "Suspicious Process",
                    classification.Reason ?? "Not part of approved environment"));
            }
        }

        bool isClean = suspicious.Count == 0;
        string statusText = isClean
            ? "Pre-Compliance Check Complete. The endpoint is ready for examination."
            : "The following applications/services are currently running and are not part of the approved examination environment. Please close them before proceeding.";

        return new PreComplianceScanResult(isClean, suspicious, statusText);
    }
}

// ── 5. Browser Policy & DNS Configuration ──────────────────────────────

/// <summary>Which registry hive a browser DNS policy value actually landed in.</summary>
public enum BrowserDnsPolicyHive
{
    /// <summary>Nothing was written, so the policy is not in effect at all.</summary>
    None = 0,

    /// <summary>
    /// Written machine-wide. This is the only authoritative location for an enterprise policy and
    /// the only outcome that counts as success.
    /// </summary>
    LocalMachine = 1,

    /// <summary>
    /// Written for the current user only, because the machine-wide write was refused. The browser
    /// does honour it for the candidate's own session, but it is strictly weaker: it does not cover
    /// other users on the box, and it sits in a hive the candidate can rewrite without elevation.
    /// Treated as a failure by <see cref="BrowserDnsPolicy.Summarize"/> so it surfaces as a warning
    /// rather than passing as a clean apply.
    /// </summary>
    CurrentUser = 2
}

/// <summary>
/// One registry value that has to be set to keep a browser off its own DNS stack. Pure data - it
/// names a write without performing one, which is what makes the required policy set assertable in
/// a unit test on a machine whose browser policy must not be touched.
/// </summary>
public sealed record BrowserDnsPolicyEntry(
    string BrowserLabel,
    string PolicyKeyPath,
    string ValueName,
    object Value,
    Microsoft.Win32.RegistryValueKind Kind,
    string Rationale);

/// <summary>The result of attempting one <see cref="BrowserDnsPolicyEntry"/>.</summary>
public sealed record BrowserDnsPolicyWriteOutcome(
    BrowserDnsPolicyEntry Entry,
    BrowserDnsPolicyHive Hive,
    string? Error = null);

/// <summary>
/// The set of browser DNS policy values SPEMCS requires, and the pure decision procedure that turns
/// per-value write outcomes into a single success verdict.
/// </summary>
/// <remarks>
/// <para>
/// Two values per browser, and both are needed - setting only one leaves a usable bypass:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>DnsOverHttpsMode=off</c> stops the browser resolving names over HTTPS to a resolver of its own
/// choosing. Without it the browser can carry queries - and arbitrary data in query names - inside a
/// TLS session to whatever host the allowlist happens to permit on 443.
/// </description></item>
/// <item><description>
/// <c>BuiltInDnsClientEnabled=0</c> stops the browser using its OWN embedded stub resolver, which
/// speaks plain DNS directly from the browser process instead of going through the Windows DNS Client
/// service. That path is not DoH, so <c>DnsOverHttpsMode</c> does not cover it, and because it
/// originates in the approved browser executable it is inside the program scope every allow rule is
/// pinned to. Forcing resolution back through the OS resolver is what makes the ETW
/// <c>Microsoft-Windows-DNS-Client</c> monitor see the queries at all.
/// </description></item>
/// </list>
/// <para>
/// Neither value is what PREVENTS DNS-based exfiltration, and nothing here should be read as
/// claiming that. Recursive DNS to the configured resolver stays permitted, by design - see the DNS
/// model documented at the <c>DisableSecureDns</c> call site in <c>AgentWorker</c> - so a candidate
/// who encodes data in query labels still has a low-bandwidth channel. These two values remove the
/// browser's ability to choose an unmonitored resolver; detection of tunnelling over the permitted
/// one is the ETW monitor's job.
/// </para>
/// </remarks>
public static class BrowserDnsPolicy
{
    /// <summary>
    /// Every required write lives under this prefix. Asserted by test so a future entry cannot
    /// quietly reach outside the enterprise-policy subtree into general machine configuration.
    /// </summary>
    public const string PolicyKeyPrefix = @"SOFTWARE\Policies\";

    public const string EdgePolicyKeyPath = @"SOFTWARE\Policies\Microsoft\Edge";
    public const string ChromePolicyKeyPath = @"SOFTWARE\Policies\Google\Chrome";

    public const string DnsOverHttpsModeValueName = "DnsOverHttpsMode";
    public const string DnsOverHttpsModeOff = "off";
    public const string BuiltInDnsClientEnabledValueName = "BuiltInDnsClientEnabled";

    /// <summary>The complete set of values <see cref="BrowserPolicyEnforcer.DisableSecureDns"/> writes.</summary>
    public static IReadOnlyList<BrowserDnsPolicyEntry> RequiredEntries { get; } = BuildRequiredEntries();

    private static IReadOnlyList<BrowserDnsPolicyEntry> BuildRequiredEntries()
    {
        (string Label, string KeyPath)[] browsers =
        [
            ("Microsoft Edge", EdgePolicyKeyPath),
            ("Google Chrome", ChromePolicyKeyPath)
        ];

        var entries = new List<BrowserDnsPolicyEntry>(browsers.Length * 2);
        foreach (var (label, keyPath) in browsers)
        {
            entries.Add(new BrowserDnsPolicyEntry(
                label,
                keyPath,
                DnsOverHttpsModeValueName,
                DnsOverHttpsModeOff,
                Microsoft.Win32.RegistryValueKind.String,
                "Denies the browser its own DoH resolver, which would tunnel name lookups - and any data encoded in them - inside TLS to a host the firewall sees only as port 443."));

            entries.Add(new BrowserDnsPolicyEntry(
                label,
                keyPath,
                BuiltInDnsClientEnabledValueName,
                0,
                Microsoft.Win32.RegistryValueKind.DWord,
                "Denies the browser its own embedded plain-DNS stub resolver, which bypasses the Windows DNS Client service and therefore the ETW monitor, and is not covered by DnsOverHttpsMode."));
        }

        return entries;
    }

    /// <summary>
    /// Decides whether the browser DNS policy was applied, from the outcome of each required write.
    /// </summary>
    /// <remarks>
    /// Pure, and separated from the registry on purpose: the honest-failure logic is the part worth
    /// testing, and it cannot be tested through <see cref="BrowserPolicyEnforcer.DisableSecureDns"/>
    /// without mutating machine-wide browser policy on the test host. Success requires that EVERY
    /// required entry landed in HKLM. A missing outcome counts as a failure rather than being
    /// ignored, so a caller that silently stops attempting an entry is caught instead of reporting
    /// a clean apply.
    /// </remarks>
    public static bool Summarize(IReadOnlyList<BrowserDnsPolicyWriteOutcome> outcomes, out string statusMessage)
    {
        ArgumentNullException.ThrowIfNull(outcomes);

        var applied = new List<string>();
        var degraded = new List<string>();
        var failed = new List<string>();

        foreach (var required in RequiredEntries)
        {
            var outcome = FindOutcome(outcomes, required);
            var label = $"{required.BrowserLabel}/{required.ValueName}";

            if (outcome is null)
            {
                failed.Add($"{label}: never attempted");
                continue;
            }

            switch (outcome.Hive)
            {
                case BrowserDnsPolicyHive.LocalMachine:
                    applied.Add(label);
                    break;
                case BrowserDnsPolicyHive.CurrentUser:
                    degraded.Add($"{label}: current-user hive only ({outcome.Error ?? "machine-wide write refused"})");
                    break;
                default:
                    failed.Add($"{label}: {outcome.Error ?? "no registry write succeeded"}");
                    break;
            }
        }

        var parts = new List<string>();
        if (applied.Count > 0)
        {
            parts.Add($"Applied machine-wide: {string.Join(", ", applied)}");
        }

        if (degraded.Count > 0)
        {
            parts.Add($"DEGRADED - {string.Join("; ", degraded)}");
        }

        if (failed.Count > 0)
        {
            parts.Add($"NOT APPLIED - {string.Join("; ", failed)}");
        }

        statusMessage = parts.Count > 0
            ? string.Join(". ", parts)
            : "No browser DNS policy entries are defined";

        return degraded.Count == 0 && failed.Count == 0 && applied.Count == RequiredEntries.Count;
    }

    private static BrowserDnsPolicyWriteOutcome? FindOutcome(
        IReadOnlyList<BrowserDnsPolicyWriteOutcome> outcomes,
        BrowserDnsPolicyEntry required)
    {
        foreach (var candidate in outcomes)
        {
            if (string.Equals(candidate.Entry.PolicyKeyPath, required.PolicyKeyPath, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(candidate.Entry.ValueName, required.ValueName, StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }
        }

        return null;
    }
}

public static class BrowserPolicyEnforcer
{
    /// <summary>
    /// Applies every <see cref="BrowserDnsPolicy.RequiredEntries"/> value, then best-effort updates
    /// the browsers' own preference files.
    /// </summary>
    /// <returns>
    /// <c>true</c> only when every required policy value landed machine-wide. An HKCU fallback
    /// returns <c>false</c>: the resulting posture really is weaker, and the caller's warning branch
    /// is the only place that says so. This used to be a hardcoded <c>true</c>, which made the
    /// warning branch in <c>AgentWorker</c> unreachable and meant a total failure to disable DoH was
    /// logged as a success.
    /// </returns>
    public static bool DisableSecureDns(out string? statusMessage)
    {
        var outcomes = new List<BrowserDnsPolicyWriteOutcome>(BrowserDnsPolicy.RequiredEntries.Count);
        foreach (var entry in BrowserDnsPolicy.RequiredEntries)
        {
            outcomes.Add(ApplyEntry(entry));
        }

        var success = BrowserDnsPolicy.Summarize(outcomes, out var policyStatus);

        var messages = new List<string> { policyStatus };
        // The preference-file pass is deliberately NOT part of `success`. It touches a per-profile
        // file that only exists once a browser has been launched, so its absence is normal and says
        // nothing about whether the policy is in force - the registry policy overrides it anyway.
        messages.AddRange(UpdateBrowserPreferenceFiles());

        statusMessage = string.Join("; ", messages);
        return success;
    }

    /// <summary>
    /// Writes one policy value, preferring HKLM and falling back to HKCU, and reports which hive won.
    /// </summary>
    private static BrowserDnsPolicyWriteOutcome ApplyEntry(BrowserDnsPolicyEntry entry)
    {
        string machineError;
        try
        {
            using var machineKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(entry.PolicyKeyPath, true);
            if (machineKey != null)
            {
                machineKey.SetValue(entry.ValueName, entry.Value, entry.Kind);
                return new BrowserDnsPolicyWriteOutcome(entry, BrowserDnsPolicyHive.LocalMachine);
            }

            machineError = "HKLM subkey could not be created";
        }
        catch (Exception ex)
        {
            // Typically UnauthorizedAccessException when the agent is not running elevated.
            machineError = ex.Message;
        }

        try
        {
            using var userKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(entry.PolicyKeyPath, true);
            if (userKey != null)
            {
                userKey.SetValue(entry.ValueName, entry.Value, entry.Kind);
                return new BrowserDnsPolicyWriteOutcome(entry, BrowserDnsPolicyHive.CurrentUser, machineError);
            }

            return new BrowserDnsPolicyWriteOutcome(
                entry,
                BrowserDnsPolicyHive.None,
                $"HKLM: {machineError}; HKCU subkey could not be created");
        }
        catch (Exception userEx)
        {
            return new BrowserDnsPolicyWriteOutcome(
                entry,
                BrowserDnsPolicyHive.None,
                $"HKLM: {machineError}; HKCU: {userEx.Message}");
        }
    }

    private static List<string> UpdateBrowserPreferenceFiles()
    {
        var messages = new List<string>();

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string[] prefPaths =
        [
            Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\Preferences"),
            Path.Combine(localAppData, @"Google\Chrome\User Data\Default\Preferences")
        ];

        foreach (var prefPath in prefPaths)
        {
            if (File.Exists(prefPath))
            {
                try
                {
                    string json = File.ReadAllText(prefPath);
                    using var doc = JsonDocument.Parse(json);
                    var dict = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                    if (dict != null)
                    {
                        dict["dns_over_https"] = new Dictionary<string, string> { { "mode", "off" } };
                        string updatedJson = JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = false });
                        File.WriteAllText(prefPath, updatedJson);
                        messages.Add($"Updated preferences file at {prefPath} (dns_over_https.mode=off)");
                    }
                }
                catch (Exception prefEx)
                {
                    messages.Add($"Preferences update note for {prefPath}: {prefEx.Message}");
                }
            }
        }

        return messages;
    }
}
