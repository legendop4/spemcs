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
    private readonly ApprovedBrowserFamily _approvedFamily;
    private readonly Dictionary<(string Path, string Hash), FileTrustResult> _cache = [];

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

    public ConfigurableProcessClassifier(
        ApprovedBrowserFamily approvedFamily = ApprovedBrowserFamily.Chrome,
        string? selfRoot = null,
        IFileTrustVerifier? trust = null,
        Func<int, ProcessInfo?>? parentResolver = null,
        string? windowsRoot = null)
    {
        _approvedFamily = approvedFamily;
        _selfRoot = Path.GetFullPath(selfRoot ?? AppContext.BaseDirectory);
        _windowsRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _trust = trust ?? new AuthenticodeTrustVerifier();
        _parentResolver = parentResolver;
    }

    public ClassificationResult Classify(ProcessInfo process) => ClassifyInternal(process, new HashSet<int>());

    private ClassificationResult ClassifyInternal(ProcessInfo process, HashSet<int> ancestry)
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

        // 5. Approved Browsers: Google Chrome & Microsoft Edge
        bool isChromeExe = string.Equals(fileName, "chrome.exe", StringComparison.OrdinalIgnoreCase);
        bool inChromeDir = full.Contains(@"Google\Chrome\Application", StringComparison.OrdinalIgnoreCase);
        bool isGooglePublisher = trust.Publisher != null && trust.Publisher.Contains("Google", StringComparison.OrdinalIgnoreCase);

        if (isChromeExe && inChromeDir && isGooglePublisher)
            return new ClassificationResult(Classification.Allowed, "approved-chrome-browser", "Approved Examination Browser", trust.Publisher, hash, "Google Chrome (Approved Exam Browser)");

        // Chrome helper / child processes
        if (inChromeDir && ChromeChildExes.Contains(fileName) && isGooglePublisher)
            return new ClassificationResult(Classification.Allowed, "approved-chrome-child", "Approved Browser Helper", trust.Publisher, hash, "Google Chrome Helper Process");

        // Microsoft Edge
        bool isEdgeExe = string.Equals(fileName, "msedge.exe", StringComparison.OrdinalIgnoreCase);
        bool inEdgeDir = full.Contains(@"Microsoft\Edge\Application", StringComparison.OrdinalIgnoreCase);
        bool isMicrosoftPublisher = trust.Publisher != null && trust.Publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

        if (isEdgeExe && inEdgeDir && isMicrosoftPublisher)
            return new ClassificationResult(Classification.Allowed, "approved-edge-browser", "Approved Examination Browser", trust.Publisher, hash, "Microsoft Edge (Approved Exam Browser)");

        // Edge helper / child processes
        if (inEdgeDir && EdgeChildExes.Contains(fileName) && isMicrosoftPublisher)
            return new ClassificationResult(Classification.Allowed, "approved-edge-child", "Approved Browser Helper", trust.Publisher, hash, "Microsoft Edge Helper Process");

        // Parent context check for approved browser child processes
        if (process.ParentProcessId is int parentId && _parentResolver is not null && ancestry.Add(process.ProcessId))
        {
            var parent = _parentResolver(parentId);
            if (parent is not null)
            {
                var parentResult = ClassifyInternal(parent, ancestry);
                if (parentResult.Classification == Classification.Allowed &&
                    (string.Equals(parentResult.Rule, "approved-chrome-browser", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(parentResult.Rule, "approved-edge-browser", StringComparison.OrdinalIgnoreCase)))
                {
                    return new ClassificationResult(Classification.Allowed, "approved-browser-child-inherited", "Approved Browser Helper", trust.Publisher, hash, "Child process of Approved Browser");
                }
            }
        }

        // 6. Explicitly forbidden applications or unapproved browsers by full executable file name
        if (KnownUnapprovedBrowserExes.Contains(fileName) ||
            (isChromeExe && (!inChromeDir || !isGooglePublisher)) ||
            (isEdgeExe && (!inEdgeDir || !isMicrosoftPublisher)))
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
        if (_cache.TryGetValue(key, out var result)) return result;
        result = _trust.Verify(path);
        _cache[key] = result;
        return result;
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
public static class BrowserPolicyEnforcer
{
    public static bool DisableSecureDns(out string? statusMessage)
    {
        var messages = new List<string>();
        bool success = true;

        string[] browserKeys = [@"Microsoft\Edge", @"Google\Chrome"];

        // 1. Configure Enterprise Policies in Registry
        foreach (var browser in browserKeys)
        {
            try
            {
                using var hklmKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey($@"SOFTWARE\Policies\{browser}", true);
                if (hklmKey != null)
                {
                    hklmKey.SetValue("DnsOverHttpsMode", "off", Microsoft.Win32.RegistryValueKind.String);
                    messages.Add($"Configured HKLM policy for {browser} (DnsOverHttpsMode=off)");
                }
            }
            catch (Exception ex)
            {
                // HKLM might require elevation, fallback to HKCU
                try
                {
                    using var hkcuKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey($@"SOFTWARE\Policies\{browser}", true);
                    if (hkcuKey != null)
                    {
                        hkcuKey.SetValue("DnsOverHttpsMode", "off", Microsoft.Win32.RegistryValueKind.String);
                        messages.Add($"Configured HKCU policy for {browser} (DnsOverHttpsMode=off)");
                    }
                }
                catch (Exception cuEx)
                {
                    messages.Add($"Registry policy for {browser}: {ex.Message}; {cuEx.Message}");
                }
            }
        }

        // 2. Configure Local Profile Preferences JSON files
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

        statusMessage = string.Join("; ", messages);
        return success;
    }
}
