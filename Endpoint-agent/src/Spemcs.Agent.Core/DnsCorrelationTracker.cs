using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Spemcs.Agent.Core;

public sealed record DnsResolutionEntry(
    string Domain,
    IPAddress ResolvedIp,
    DateTimeOffset TimestampUtc,
    int? ProcessId = null,
    string? ProcessName = null,
    TimeSpan? Ttl = null);

public interface IDnsCorrelationTracker
{
    void RecordResolution(string domain, IPAddress resolvedIp, DateTimeOffset timestampUtc, int? processId = null, string? processName = null, TimeSpan? ttl = null);
    bool TryCorrelate(IPAddress remoteIp, int processId, string? processName, DateTimeOffset connectionTime, out string? domain, out bool dnsResolved);
    bool TryCorrelate(IPAddress remoteIp, int processId, string? processName, DateTimeOffset connectionTime, out string? domain, out bool dnsResolved, out string? resolvedIpStr, out string? confidence);
    int ActiveEntryCount { get; }
    void Clear();
}

public sealed class DnsCorrelationTracker : IDnsCorrelationTracker
{
    private readonly ConcurrentDictionary<IPAddress, List<DnsResolutionEntry>> _ipToDomainMap = new();
    private readonly TimeSpan _maxRetentionWindow;
    private readonly int _maxEntries;
    private int _totalCount = 0;

    public DnsCorrelationTracker(TimeSpan? maxRetentionWindow = null, int maxEntries = 5000)
    {
        _maxRetentionWindow = maxRetentionWindow ?? TimeSpan.FromMinutes(10);
        _maxEntries = maxEntries;
    }

    public int ActiveEntryCount => _totalCount;

    public void Clear()
    {
        _ipToDomainMap.Clear();
        _totalCount = 0;
    }

    public void RecordResolution(string domain, IPAddress resolvedIp, DateTimeOffset timestampUtc, int? processId = null, string? processName = null, TimeSpan? ttl = null)
    {
        if (string.IsNullOrWhiteSpace(domain) || resolvedIp == null) return;

        var cleanDomain = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (cleanDomain.Length == 0) return;

        if (cleanDomain.EndsWith(".local") || cleanDomain.EndsWith(".arpa") || cleanDomain.Equals("localhost")) return;

        var entry = new DnsResolutionEntry(cleanDomain, resolvedIp, timestampUtc, processId, processName, ttl);

        var entries = _ipToDomainMap.GetOrAdd(resolvedIp, _ => new List<DnsResolutionEntry>());
        lock (entries)
        {
            entries.RemoveAll(e => e.Domain.Equals(cleanDomain, StringComparison.OrdinalIgnoreCase));
            entries.Add(entry);

            if (entries.Count > 10)
            {
                entries.RemoveAt(0);
            }
        }

        System.Threading.Interlocked.Increment(ref _totalCount);

        if (_totalCount > _maxEntries)
        {
            PruneExpiredEntries();
        }
    }

    public bool TryCorrelate(IPAddress remoteIp, int processId, string? processName, DateTimeOffset connectionTime, out string? domain, out bool dnsResolved)
    {
        return TryCorrelate(remoteIp, processId, processName, connectionTime, out domain, out dnsResolved, out _, out _);
    }

    public bool TryCorrelate(IPAddress remoteIp, int processId, string? processName, DateTimeOffset connectionTime, out string? domain, out bool dnsResolved, out string? resolvedIpStr, out string? confidence)
    {
        domain = null;
        dnsResolved = false;
        resolvedIpStr = remoteIp?.ToString();
        confidence = "unresolved";

        if (remoteIp == null || !_ipToDomainMap.TryGetValue(remoteIp, out var entries))
        {
            return false;
        }

        var cutoff = connectionTime - _maxRetentionWindow;

        lock (entries)
        {
            entries.RemoveAll(e => e.TimestampUtc < cutoff);

            if (entries.Count == 0)
            {
                return false;
            }

            // 1. Try matching both ProcessId and IP recency -> HIGH confidence
            var pidMatch = entries
                .Where(e => e.ProcessId.HasValue && e.ProcessId.Value == processId)
                .OrderByDescending(e => e.TimestampUtc)
                .FirstOrDefault();

            if (pidMatch != null)
            {
                domain = pidMatch.Domain;
                dnsResolved = true;
                confidence = "high";
                return true;
            }

            // 2. Try matching ProcessName and IP recency -> MEDIUM confidence
            if (!string.IsNullOrWhiteSpace(processName))
            {
                var nameMatch = entries
                    .Where(e => !string.IsNullOrWhiteSpace(e.ProcessName) && e.ProcessName.Equals(processName, StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(e => e.TimestampUtc)
                    .FirstOrDefault();

                if (nameMatch != null)
                {
                    domain = nameMatch.Domain;
                    dnsResolved = true;
                    confidence = "medium";
                    return true;
                }
            }

            // 3. Fallback to most recent DNS resolution for this IP -> MEDIUM confidence
            var mostRecent = entries
                .OrderByDescending(e => e.TimestampUtc)
                .FirstOrDefault();

            if (mostRecent != null)
            {
                domain = mostRecent.Domain;
                dnsResolved = true;
                confidence = "medium";
                return true;
            }
        }

        return false;
    }

    public void PruneExpiredEntries()
    {
        var cutoff = DateTimeOffset.UtcNow - _maxRetentionWindow;
        int count = 0;

        foreach (var kvp in _ipToDomainMap)
        {
            lock (kvp.Value)
            {
                kvp.Value.RemoveAll(e => e.TimestampUtc < cutoff);
                count += kvp.Value.Count;
            }
        }

        _totalCount = count;
    }
}
