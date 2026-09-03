using System.Diagnostics;
using Microsoft.Data.Sqlite;
using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class LiveDetectionTests
{
    [Fact]
    public void Real_time_process_monitor_detects_app_opened_and_closed_events()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), "spemcs-live-test", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(dbPath);
            store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-PC", "127.0.0.1", DateTimeOffset.UtcNow));
            store.SaveState(AgentState.Monitoring, new AgentSession("ses_1", "STU-99", DateTimeOffset.UtcNow, ApprovedBrowserFamily.Chrome));

            var source = new WindowsProcessSource();
            var classifier = new TestProcessClassifier();
            var events = new List<ViolationEvent>();
            var mockPublisher = new TestPublisher(events);

            var monitor = new ProcessMonitor(source, classifier, store, store.LoadSnapshot, mockPublisher);
            var uploader = new EventUploaderWorker(store, mockPublisher, pollInterval: TimeSpan.FromMilliseconds(100));

            // 1. Start continuous background monitor loop and event uploader
            uploader.Start();
            monitor.Start();

            // 2. Launch cmd.exe live (deterministic Win32 process)
            using var proc = Process.Start(new ProcessStartInfo("cmd.exe", "/c ping 127.0.0.1 -n 10") 
            { 
                CreateNoWindow = true, 
                UseShellExecute = false 
            });
            Assert.NotNull(proc);

            // 3. Wait for background 1-second timer loop to detect APPLICATION_OPENED live
            ViolationEvent? openEvent = null;
            for (int i = 0; i < 20; i++)
            {
                lock (events)
                {
                    openEvent = events.FirstOrDefault(e => e.ProcessId == proc.Id && e.EventType == EventTypes.ApplicationOpened);
                }
                if (openEvent is not null) break;
                Thread.Sleep(500);
            }

            Assert.NotNull(openEvent);
            Assert.Equal(EventTypes.ApplicationOpened, openEvent.EventType);
            Assert.Equal(proc.Id, openEvent.ProcessId);

            // 4. Kill cmd.exe live
            try { proc.Kill(true); proc.WaitForExit(3000); } catch { }

            // 5. Wait for background 1-second timer loop to detect APPLICATION_CLOSED live
            ViolationEvent? closeEvent = null;
            for (int i = 0; i < 20; i++)
            {
                lock (events)
                {
                    closeEvent = events.FirstOrDefault(e => e.ProcessId == proc.Id && e.EventType == EventTypes.ApplicationClosed);
                }
                if (closeEvent is not null) break;
                Thread.Sleep(500);
            }

            Assert.NotNull(closeEvent);
            Assert.Equal(EventTypes.ApplicationClosed, closeEvent.EventType);
            Assert.Equal(proc.Id, closeEvent.ProcessId);

            monitor.Stop();
            uploader.Stop();
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            try { if (Directory.Exists(dbPath)) Directory.Delete(dbPath, true); } catch { }
        }
    }

    private sealed class TestProcessClassifier : IProcessClassifier
    {
        public ClassificationResult Classify(ProcessInfo process)
        {
            if (process.Name.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) || process.Name.Equals("cmd", StringComparison.OrdinalIgnoreCase))
            {
                return new ClassificationResult(Classification.Suspicious, "unapproved-app", "Unapproved Application", null, null, "Test suspicious process");
            }
            return new ClassificationResult(Classification.Allowed, "allowed-app", "Allowed", null, null, "Allowed process");
        }
    }

    private sealed class TestPublisher(List<ViolationEvent> target) : IEventPublisher
    {
        public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
        {
            lock (target)
            {
                target.Add(violation);
            }
            return Task.CompletedTask;
        }
    }
}
