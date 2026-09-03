using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Text.Json;

namespace Spemcs.Agent.Service;

public sealed class RollingFileLoggerProvider : ILoggerProvider
{
    private readonly string _directory;
    private readonly long _maxBytes;
    private readonly ConcurrentDictionary<string, RollingFileLogger> _loggers = new(StringComparer.Ordinal);
    public RollingFileLoggerProvider(string directory, long maxBytes = 10 * 1024 * 1024) { _directory = directory; _maxBytes = maxBytes; Directory.CreateDirectory(directory); }
    public ILogger CreateLogger(string categoryName) => _loggers.GetOrAdd(categoryName, c => new RollingFileLogger(_directory, _maxBytes, c));
    public void Dispose() { foreach (var logger in _loggers.Values) logger.Dispose(); _loggers.Clear(); }
}

internal sealed class RollingFileLogger : ILogger, IDisposable
{
    private readonly string _directory; private readonly long _maxBytes; private readonly string _category; private readonly object _gate = new(); private StreamWriter? _writer; private string? _path;
    public RollingFileLogger(string directory, long maxBytes, string category) { _directory=directory; _maxBytes=maxBytes; _category=category; }
    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;
        var record = new { TimestampUtc=DateTimeOffset.UtcNow, Level=logLevel.ToString(), Category=_category, EventId=eventId.Id, Message=formatter(state, exception), Exception=exception?.ToString() };
        var line = JsonSerializer.Serialize(record);
        lock (_gate)
        {
            EnsureWriter(line.Length + Environment.NewLine.Length);
            _writer!.WriteLine(line); _writer.Flush();
        }
    }
    private void EnsureWriter(int incomingBytes)
    {
        var path = Path.Combine(_directory, $"agent-{DateTime.UtcNow:yyyyMMdd}.log");
        if (_writer is null || !string.Equals(_path, path, StringComparison.OrdinalIgnoreCase) || (_writer.BaseStream.Length + incomingBytes > _maxBytes))
        {
            _writer?.Dispose(); _path = path; var suffix = 0; var candidate = path;
            while (File.Exists(candidate) && new FileInfo(candidate).Length + incomingBytes > _maxBytes) candidate = Path.Combine(_directory, $"agent-{DateTime.UtcNow:yyyyMMdd}-{++suffix}.log");
            _path = candidate; _writer = new StreamWriter(new FileStream(candidate, FileMode.Append, FileAccess.Write, FileShare.ReadWrite)) { AutoFlush = true };
        }
    }
    public void Dispose() { lock (_gate) { _writer?.Dispose(); _writer = null; } }
    private sealed class NullScope : IDisposable { public static readonly NullScope Instance = new(); public void Dispose() { } }
}
