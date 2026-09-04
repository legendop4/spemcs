using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Spemcs.Agent.Core;

public readonly record struct ConnectionIdentity(
    int ProcessId,
    string Protocol,
    string LocalIp,
    int LocalPort,
    string RemoteIp,
    int RemotePort);

public sealed record NetworkConnectionInfo(
    int ProcessId,
    string ProcessName,
    string? ExecutablePath,
    string Protocol,
    string LocalIp,
    int LocalPort,
    string RemoteIp,
    int RemotePort,
    string State,
    string? Domain,
    DateTimeOffset TimestampUtc,
    bool DnsResolved = false);

public interface INetworkTableProvider
{
    IReadOnlyList<NetworkConnectionInfo> GetActiveTcpConnections();
}

public sealed class Win32NetworkTableProvider : INetworkTableProvider
{
    private readonly IProcessSource _processSource;
    private readonly IDnsCorrelationTracker _dnsTracker;
    private readonly ConcurrentDictionary<string, string> _dnsCache = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _lastDnsScan = DateTimeOffset.MinValue;

    public Win32NetworkTableProvider(IProcessSource? processSource = null, IDnsCorrelationTracker? dnsTracker = null)
    {
        _processSource = processSource ?? new WindowsProcessSource();
        _dnsTracker = dnsTracker ?? new DnsCorrelationTracker();
    }

    public IReadOnlyList<NetworkConnectionInfo> GetActiveTcpConnections()
    {
        RefreshDnsCacheIfNeeded();

        var result = new List<NetworkConnectionInfo>();
        IntPtr pTable = IntPtr.Zero;
        int size = 0;

        try
        {
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2 /* AF_INET */, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
            if (size <= 0) return result;

            pTable = Marshal.AllocHGlobal(size);
            ret = GetExtendedTcpTable(pTable, ref size, false, 2, 5, 0);
            if (ret != 0) return result;

            int numEntries = Marshal.ReadInt32(pTable);
            IntPtr rowPtr = IntPtr.Add(pTable, 4);

            var processMap = new Dictionary<int, (string Name, string? Path)>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_TCPROW_OWNER_PID>());

                int pid = (int)row.owningPid;
                if (pid <= 0) continue;

                var state = row.TcpState.ToString();
                var localIp = row.LocalIpAddress.ToString();
                var remoteIp = row.RemoteIpAddress.ToString();

                if (!processMap.TryGetValue(pid, out var procMeta))
                {
                    var pInfo = _processSource.FindById(pid);
                    procMeta = (pInfo?.Name ?? $"pid-{pid}", pInfo?.ExecutablePath);
                    processMap[pid] = procMeta;
                }

                string? domain = null;
                bool dnsResolved = false;

                if (IPAddress.TryParse(remoteIp, out var remoteIpObj))
                {
                    if (_dnsTracker.TryCorrelate(remoteIpObj, pid, procMeta.Name, DateTimeOffset.UtcNow, out var correlatedDomain, out var isResolved))
                    {
                        domain = correlatedDomain;
                        dnsResolved = isResolved;
                    }
                }

                if (domain == null && _dnsCache.TryGetValue(remoteIp, out var legacyDomain))
                {
                    domain = legacyDomain;
                    dnsResolved = true;
                }

                result.Add(new NetworkConnectionInfo(
                    pid,
                    procMeta.Name,
                    procMeta.Path,
                    "TCP",
                    localIp,
                    row.LocalPort,
                    remoteIp,
                    row.RemotePort,
                    state,
                    domain,
                    DateTimeOffset.UtcNow,
                    dnsResolved));
            }
        }
        catch
        {
            // Fail safe on OS/PInvoke exceptions
        }
        finally
        {
            if (pTable != IntPtr.Zero) Marshal.FreeHGlobal(pTable);
        }

        return result;
    }

    private void RefreshDnsCacheIfNeeded()
    {
        if (DateTimeOffset.UtcNow - _lastDnsScan < TimeSpan.FromSeconds(10)) return;
        _lastDnsScan = DateTimeOffset.UtcNow;

        try
        {
            IntPtr pEntry;
            int res = DnsGetCacheDataTable(out pEntry);
            if (res != 0 || pEntry == IntPtr.Zero) return;

            IntPtr current = pEntry;
            while (current != IntPtr.Zero)
            {
                var entry = Marshal.PtrToStructure<DNS_CACHE_ENTRY>(current);
                if (!string.IsNullOrWhiteSpace(entry.recName))
                {
                    var domain = entry.recName.Trim().ToLowerInvariant();
                    // Read Win32 DNS Client cache record names
                    if (!domain.EndsWith(".local") && !domain.EndsWith(".arpa"))
                    {
                        _dnsCache[domain] = domain;
                    }
                }
                current = entry.pNext;
            }
        }
        catch
        {
            // Best-effort non-blocking DNS cache reader
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint remoteAddr;
        public byte remotePort1;
        public byte remotePort2;
        public byte remotePort3;
        public byte remotePort4;
        public uint owningPid;

        public readonly ushort LocalPort => (ushort)((localPort1 << 8) + localPort2);
        public readonly ushort RemotePort => (ushort)((remotePort1 << 8) + remotePort2);
        public readonly IPAddress LocalIpAddress => new(localAddr);
        public readonly IPAddress RemoteIpAddress => new(remoteAddr);
        public readonly TcpState TcpState => (TcpState)state;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DNS_CACHE_ENTRY
    {
        public IntPtr pNext;
        public string recName;
        public ushort wType;
        public ushort wDataLength;
        public uint dwFlags;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, uint ulAf, uint TableClass, uint Reserved);

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", CharSet = CharSet.Unicode)]
    private static extern int DnsGetCacheDataTable(out IntPtr pNext);
}

/// <summary>
/// Native background Windows network telemetry collector that monitors TCP connections,
/// correlates originating PID with process metadata, deduplicates active sockets, and enqueues events.
/// </summary>
public sealed class NetworkCollector
{
    private readonly IAgentStore _store;
    private readonly INetworkTableProvider _tableProvider;
    private readonly NetworkPolicyEvaluator _policyEvaluator;
    private readonly IDnsCorrelationTracker _dnsTracker;
    private readonly Func<AgentSnapshot>? _snapshotProvider;
    private readonly ILogger? _log;
    private readonly TimeSpan _pollInterval;
    private IEtwDnsListener? _etwListener;
    private CancellationTokenSource? _cts;
    private Task? _collectorTask;
    private readonly object _lock = new();

    private readonly Dictionary<ConnectionIdentity, NetworkConnectionInfo> _activeConnections = new();

    public bool IsRunning { get; private set; }
    public int ActiveConnectionCount { get { lock (_activeConnections) return _activeConnections.Count; } }
    public IDnsCorrelationTracker DnsTracker => _dnsTracker;

    /// <param name="approvedBrowser">
    /// Shared approved-browser context, threaded into the default
    /// <see cref="NetworkPolicyEvaluator"/> so that network findings are judged against the browser
    /// the SIGNED policy approved. Ignored when an explicit
    /// <paramref name="policyEvaluator"/> is supplied - that instance carries its own context.
    /// </param>
    public NetworkCollector(
        IAgentStore store,
        INetworkTableProvider? tableProvider = null,
        NetworkPolicyEvaluator? policyEvaluator = null,
        IDnsCorrelationTracker? dnsTracker = null,
        Func<AgentSnapshot>? snapshotProvider = null,
        ILogger? log = null,
        TimeSpan? pollInterval = null,
        IApprovedBrowserContext? approvedBrowser = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _dnsTracker = dnsTracker ?? new DnsCorrelationTracker();
        _tableProvider = tableProvider ?? new Win32NetworkTableProvider(dnsTracker: _dnsTracker);
        _policyEvaluator = policyEvaluator ?? new NetworkPolicyEvaluator(approvedBrowser: approvedBrowser);
        _snapshotProvider = snapshotProvider;
        _log = log;
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(2);
    }

    public void Start()
    {
        lock (_lock)
        {
            if (IsRunning) return;
            _cts = new CancellationTokenSource();
            IsRunning = true;

            try
            {
                _etwListener = new EtwDnsListener(_dnsTracker, _log);
                _etwListener.Start();
            }
            catch (Exception ex)
            {
                _log?.LogWarning(ex, "Failed to start EtwDnsListener");
            }

            _collectorTask = Task.Run(() => RunLoopAsync(_cts.Token));
            _log?.LogInformation("NetworkCollector background loop started with interval {Interval}s.", _pollInterval.TotalSeconds);
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            if (!IsRunning) return;
            _cts?.Cancel();

            try { _etwListener?.Stop(); _etwListener?.Dispose(); } catch { }
            _etwListener = null;

            try { _collectorTask?.Wait(TimeSpan.FromSeconds(3)); } catch { }
            _cts?.Dispose();
            _cts = null;
            _collectorTask = null;
            IsRunning = false;
            _log?.LogInformation("NetworkCollector background loop stopped.");
        }
    }

    public int PollOnce()
    {
        try
        {
            var currentConnections = _tableProvider.GetActiveTcpConnections();
            var currentIdentities = new HashSet<ConnectionIdentity>();
            int newEventsCount = 0;

            var snapshot = _snapshotProvider?.Invoke();
            var deviceName = snapshot?.Registration?.DeviceName ?? Environment.MachineName;
            var rollNumber = snapshot?.Session?.StudentRollNumber;

            lock (_activeConnections)
            {
                foreach (var conn in currentConnections)
                {
                    var identity = new ConnectionIdentity(
                        conn.ProcessId,
                        conn.Protocol,
                        conn.LocalIp,
                        conn.LocalPort,
                        conn.RemoteIp,
                        conn.RemotePort);

                    currentIdentities.Add(identity);

                    if (!_activeConnections.ContainsKey(identity))
                    {
                        // New connection discovered -> perform DNS correlation first
                        _activeConnections[identity] = conn;

                        string? confidence = "unresolved";
                        string? resolvedIpStr = conn.RemoteIp;
                        string? correlatedDomain = conn.Domain;
                        bool isResolved = conn.DnsResolved;

                        if (IPAddress.TryParse(conn.RemoteIp, out var remoteIpObj))
                        {
                            if (_dnsTracker.TryCorrelate(remoteIpObj, conn.ProcessId, conn.ProcessName, conn.TimestampUtc, out var trackerDomain, out var trackerResolved, out resolvedIpStr, out confidence))
                            {
                                correlatedDomain = trackerDomain;
                                isResolved = trackerResolved;
                            }
                        }

                        var connWithDomain = conn with { Domain = correlatedDomain, DnsResolved = isResolved };
                        var evalResult = _policyEvaluator.Evaluate(connWithDomain);

                        if (evalResult.IsPromoted)
                        {
                            var reasonStr = evalResult.Reason ?? $"{conn.Protocol} {conn.LocalIp}:{conn.LocalPort} -> {conn.RemoteIp}:{conn.RemotePort} ({conn.State})";

                            if (!string.IsNullOrWhiteSpace(correlatedDomain) && !reasonStr.Contains("domain:"))
                            {
                                reasonStr += $" [domain: {correlatedDomain}]";
                            }

                            var netEvent = new ViolationEvent(
                                Guid.NewGuid(),
                                deviceName,
                                rollNumber,
                                evalResult.EventType ?? EventTypes.NetworkConnection,
                                conn.ProcessId,
                                conn.ProcessName,
                                conn.TimestampUtc,
                                conn.ExecutablePath,
                                reasonStr,
                                Domain: correlatedDomain,
                                DnsResolved: isResolved,
                                DnsResolvedIp: resolvedIpStr,
                                DnsConfidence: confidence);

                            _store.Enqueue(netEvent);
                            newEventsCount++;

                            _log?.LogInformation("PROMOTED SECURITY EVENT [{Severity}]: type={EventType} pid={Pid} name={Name} remote={RemoteIp}:{RemotePort} domain={Domain}",
                                evalResult.Severity, evalResult.EventType, conn.ProcessId, conn.ProcessName, conn.RemoteIp, conn.RemotePort, correlatedDomain ?? "N/A");
                        }
                        else
                        {
                            _log?.LogDebug("SUPPRESSED BENIGN CONNECTION: pid={Pid} name={Name} remote={RemoteIp}:{RemotePort}",
                                conn.ProcessId, conn.ProcessName, conn.RemoteIp, conn.RemotePort);
                        }
                    }
                }

                // Remove closed / disappeared connections from bounded active cache
                var disappeared = _activeConnections.Keys.Where(k => !currentIdentities.Contains(k)).ToList();
                foreach (var key in disappeared)
                {
                    _activeConnections.Remove(key);
                }
            }

            return newEventsCount;
        }
        catch (Exception ex)
        {
            _log?.LogError(ex, "Error during NetworkCollector polling cycle");
            return 0;
        }
    }


    private async Task RunLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            PollOnce();
            try
            {
                await Task.Delay(_pollInterval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
