using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Spemcs.Agent.Core;

public sealed record PolicyEvaluationResult(
    bool IsPromoted,
    string? EventType,
    string? Severity,
    string? Reason)
{
    public static PolicyEvaluationResult Suppressed { get; } = new(false, null, null, null);
    public static PolicyEvaluationResult Promote(string eventType, string severity, string reason) => new(true, eventType, severity, reason);
}

public sealed class NetworkPolicyOptions
{
    public HashSet<string> ProhibitedProcesses { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "anydesk", "anydesk.exe",
        "teamviewer", "teamviewer.exe", "teamviewer_service.exe",
        "dwagent", "dwagent.exe", "dwagsvc.exe",
        "vnc", "vncviewer.exe", "winvnc.exe",
        "discord", "discord.exe",
        "telegram", "telegram.exe",
        "chatgpt", "chatgpt.exe"
    };

    public HashSet<string> BenignProcesses { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "svchost.exe",
        "system",
        "explorer", "explorer.exe",
        "spemcs.agent.ui", "spemcs.agent.ui.exe",
        "spemcs.agent.service", "spemcs.agent.service.exe"
    };

    public HashSet<string> ApprovedBrowsers { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "chrome.exe",
        "msedge", "msedge.exe",
        "firefox", "firefox.exe",
        "brave", "brave.exe",
        "opera", "opera.exe"
    };

    public HashSet<string> ProhibitedDomains { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "chatgpt.com",
        "openai.com",
        "claude.ai",
        "poe.com"
    };

    public HashSet<int> StandardWebPorts { get; set; } = new() { 80, 443 };

    public bool EnableUnclassifiedRule { get; set; } = true;
    public int BurstThresholdCount { get; set; } = 3;
    public TimeSpan BurstWindow { get; set; } = TimeSpan.FromSeconds(10);
}

public sealed class NetworkPolicyEvaluator
{
    private readonly NetworkPolicyOptions _options;
    private readonly ConcurrentDictionary<int, List<(string RemoteIp, DateTimeOffset Time)>> _burstTracker = new();

    public NetworkPolicyEvaluator(NetworkPolicyOptions? options = null)
    {
        _options = options ?? new NetworkPolicyOptions();
    }

    public static bool IsProhibitedDomain(string? domain, IEnumerable<string> prohibitedDomains)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var cleanDomain = domain.Trim().ToLowerInvariant().TrimEnd('.');
        foreach (var p in prohibitedDomains)
        {
            var cleanP = p.Trim().ToLowerInvariant().TrimEnd('.');
            if (cleanDomain.Equals(cleanP, StringComparison.OrdinalIgnoreCase) ||
                cleanDomain.EndsWith("." + cleanP, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    public PolicyEvaluationResult Evaluate(NetworkConnectionInfo conn, ClassificationResult? classification = null)
    {
        var procName = conn.ProcessName ?? "";
        var procNameLower = procName.ToLowerInvariant().Replace(".exe", "");
        var execPath = conn.ExecutablePath ?? "";
        var remoteIp = conn.RemoteIp ?? "";
        var remotePort = conn.RemotePort;
        var socketStr = $"{conn.LocalIp}:{conn.LocalPort} -> {remoteIp}:{remotePort}";

        // Signal 1: Localhost / Loopback / Listening sockets -> ALWAYS SUPPRESSED
        if (IsLoopbackOrLocalhost(conn))
        {
            return PolicyEvaluationResult.Suppressed;
        }

        // Rule — Prohibited domain access (e.g. browser or any process connecting to chatgpt.com / claude.ai) -> CRITICAL
        if (!string.IsNullOrWhiteSpace(conn.Domain) && IsProhibitedDomain(conn.Domain, _options.ProhibitedDomains))
        {
            return PolicyEvaluationResult.Promote(
                "PROHIBITED_DOMAIN_ACCESS",
                "CRITICAL",
                $"Process '{procName}' (PID {conn.ProcessId}) accessed prohibited domain '{conn.Domain}' ({socketStr})");
        }

        // Rule A — Prohibited process + network activity -> CRITICAL / HIGH
        if (_options.ProhibitedProcesses.Contains(procName) || _options.ProhibitedProcesses.Contains(procNameLower))
        {
            if (!_options.StandardWebPorts.Contains(remotePort))
            {
                return PolicyEvaluationResult.Promote(
                    EventTypes.AnomalousPortViolation,
                    "HIGH",
                    $"Prohibited process '{procName}' (PID {conn.ProcessId}) opened connection to non-standard remote port {remotePort} ({socketStr})");
            }

            return PolicyEvaluationResult.Promote(
                EventTypes.ProhibitedProcessNetwork,
                "CRITICAL",
                $"Prohibited process '{procName}' (PID {conn.ProcessId}) established network connection ({socketStr})");
        }

        // Rule B — Suspicious executable path + external connection -> HIGH
        if (!string.IsNullOrWhiteSpace(execPath) && IsUserWritablePath(execPath))
        {
            if (!execPath.Contains("Spemcs", StringComparison.OrdinalIgnoreCase))
            {
                return PolicyEvaluationResult.Promote(
                    EventTypes.SuspiciousPathNetwork,
                    "HIGH",
                    $"Process '{procName}' running from user-writable directory ({execPath}) established connection ({socketStr})");
            }
        }

        // Check if benign process or approved browser
        bool isBenignProc = _options.BenignProcesses.Contains(procName) || _options.BenignProcesses.Contains(procNameLower);
        bool isApprovedBrowser = _options.ApprovedBrowsers.Contains(procName) || _options.ApprovedBrowsers.Contains(procNameLower);

        if (isApprovedBrowser && _options.StandardWebPorts.Contains(remotePort))
        {
            return PolicyEvaluationResult.Suppressed;
        }

        if (isBenignProc)
        {
            return PolicyEvaluationResult.Suppressed;
        }

        // Rule D — Suspicious process + unusual destination port -> HIGH
        bool isSuspiciousClass = classification?.Classification == Classification.Suspicious;
        if (isSuspiciousClass && !_options.StandardWebPorts.Contains(remotePort))
        {
            return PolicyEvaluationResult.Promote(
                EventTypes.AnomalousPortViolation,
                "HIGH",
                $"Suspicious process '{procName}' (PID {conn.ProcessId}) opened connection to non-standard remote port {remotePort} ({socketStr})");
        }

        // Rule E — Repeated anomalous connection burst -> HIGH
        if (CheckBurstThreshold(conn.ProcessId, remoteIp))
        {
            return PolicyEvaluationResult.Promote(
                EventTypes.BurstConnectionAnomaly,
                "HIGH",
                $"Process '{procName}' (PID {conn.ProcessId}) triggered burst connection anomaly to multiple external destinations within {_options.BurstWindow.TotalSeconds}s ({socketStr})");
        }

        // Rule C — Unknown process + external connection -> MEDIUM (if enabled)
        if (_options.EnableUnclassifiedRule && !string.IsNullOrWhiteSpace(execPath) && !isBenignProc && !isApprovedBrowser)
        {
            return PolicyEvaluationResult.Promote(
                EventTypes.UnclassifiedProcessNetwork,
                "MEDIUM",
                $"Unclassified process '{procName}' (PID {conn.ProcessId}, path: {execPath}) established external connection ({socketStr})");
        }

        return PolicyEvaluationResult.Suppressed;
    }

    private static bool IsLoopbackOrLocalhost(NetworkConnectionInfo conn)
    {
        if (conn.State.Equals("Listen", StringComparison.OrdinalIgnoreCase)) return true;
        if (conn.LocalIp == "127.0.0.1" && conn.RemoteIp == "127.0.0.1") return true;
        if (conn.LocalIp == "::1" && conn.RemoteIp == "::1") return true;
        if (conn.RemoteIp == "0.0.0.0" || conn.RemoteIp == "::" || conn.RemoteIp == "127.0.0.1" || conn.RemoteIp == "::1") return true;
        return false;
    }

    private static bool IsUserWritablePath(string path)
    {
        var p = path.ToLowerInvariant();
        return p.Contains("\\appdata\\") ||
               p.Contains("\\temp\\") ||
               p.Contains("\\downloads\\") ||
               p.Contains("\\users\\public\\");
    }

    private bool CheckBurstThreshold(int pid, string remoteIp)
    {
        var now = DateTimeOffset.UtcNow;
        var cutoff = now - _options.BurstWindow;

        var history = _burstTracker.GetOrAdd(pid, _ => new List<(string RemoteIp, DateTimeOffset Time)>());
        lock (history)
        {
            history.RemoveAll(x => x.Time < cutoff);
            history.Add((remoteIp, now));

            var distinctRemoteIps = history.Select(x => x.RemoteIp).Distinct().Count();
            return distinctRemoteIps >= _options.BurstThresholdCount;
        }
    }
}
