using System;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Spemcs.Agent.Core;

public interface IEtwDnsListener : IDisposable
{
    void Start();
    void Stop();
    bool IsRunning { get; }
}

public sealed class EtwDnsListener : IEtwDnsListener
{
    private readonly IDnsCorrelationTracker _tracker;
    private readonly ILogger? _log;
    private EventLogWatcher? _watcher;
    private CancellationTokenSource? _cts;
    private Task? _pollTask;
    private readonly object _lock = new();
    private DateTime _lastReadTime = DateTime.UtcNow.AddSeconds(-30);

    private static readonly Regex IpRegex = new(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled);
    private static readonly Regex PidRegex = new(@"\bclient PID\s+(\d+)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex NameRegex = new(@"\bname\s+([a-zA-Z0-9\.\-_]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public bool IsRunning { get; private set; }

    public EtwDnsListener(IDnsCorrelationTracker tracker, ILogger? log = null)
    {
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _log = log;
    }

    public void Start()
    {
        lock (_lock)
        {
            if (IsRunning) return;
            IsRunning = true;
            _cts = new CancellationTokenSource();

            try
            {
                var query = new EventLogQuery("Microsoft-Windows-DNS-Client/Operational", PathType.LogName, "*[System[(EventID=3008 or EventID=3010 or EventID=3011 or EventID=3018 or EventID=3020)]]");
                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += OnEventRecordWritten;
                _watcher.Enabled = true;
                _log?.LogInformation("EtwDnsListener event log watcher started on Microsoft-Windows-DNS-Client/Operational.");
            }
            catch (Exception ex)
            {
                _log?.LogWarning(ex, "Could not start EventLogWatcher on Microsoft-Windows-DNS-Client/Operational. Falling back to periodic poll mode.");
                _pollTask = Task.Run(() => PollLoopAsync(_cts.Token));
            }
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            if (!IsRunning) return;
            IsRunning = false;
            _cts?.Cancel();

            if (_watcher != null)
            {
                try
                {
                    _watcher.Enabled = false;
                    _watcher.EventRecordWritten -= OnEventRecordWritten;
                    _watcher.Dispose();
                }
                catch { }
                _watcher = null;
            }

            try { _pollTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
            _cts?.Dispose();
            _cts = null;
            _pollTask = null;

            _log?.LogInformation("EtwDnsListener stopped.");
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null) return;
        try
        {
            ProcessEventRecord(e.EventRecord);
        }
        catch (Exception ex)
        {
            _log?.LogDebug(ex, "Error processing DNS event record.");
        }
    }

    public void ProcessEventRecord(EventRecord record)
    {
        var msg = record.FormatDescription();
        if (string.IsNullOrWhiteSpace(msg))
        {
            // Parse payload properties if FormatDescription is empty
            try
            {
                var props = record.Properties.Select(p => p.Value?.ToString() ?? "").ToList();
                msg = string.Join(" ", props);
            }
            catch { return; }
        }

        int? pid = null;
        var pidMatch = PidRegex.Match(msg);
        if (pidMatch.Success && int.TryParse(pidMatch.Groups[1].Value, out var parsedPid))
        {
            pid = parsedPid;
        }

        string? domain = null;
        var nameMatch = NameRegex.Match(msg);
        if (nameMatch.Success)
        {
            domain = nameMatch.Groups[1].Value;
        }

        if (string.IsNullOrWhiteSpace(domain)) return;

        var ipMatches = IpRegex.Matches(msg);
        foreach (Match match in ipMatches)
        {
            if (IPAddress.TryParse(match.Value, out var ip))
            {
                _tracker.RecordResolution(domain, ip, record.TimeCreated ?? DateTimeOffset.UtcNow, processId: pid);
            }
        }
    }

    private async Task PollLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var queryText = $"*[System[(EventID=3008 or EventID=3010 or EventID=3011 or EventID=3018 or EventID=3020) and TimeCreated[@SystemTime>='{_lastReadTime:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";
                var query = new EventLogQuery("Microsoft-Windows-DNS-Client/Operational", PathType.LogName, queryText);

                using var reader = new EventLogReader(query);
                EventRecord? rec;
                while ((rec = reader.ReadEvent()) != null)
                {
                    using (rec)
                    {
                        ProcessEventRecord(rec);
                        if (rec.TimeCreated.HasValue && rec.TimeCreated.Value > _lastReadTime)
                        {
                            _lastReadTime = rec.TimeCreated.Value;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log?.LogDebug(ex, "Error polling DNS operational log.");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken); } catch { break; }
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
