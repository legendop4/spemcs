using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class PreComplianceSafetyTests
{
    [Fact]
    public void Essential_windows_components_are_allowed_and_do_not_appear_in_suspicious_list()
    {
        var essential = new ProcessInfo(1, "svchost", "C:\\Windows\\System32\\svchost.exe", null, false);
        var suspicious = new ProcessInfo(2, "notepad", "C:\\Users\\student\\notepad.exe", null, true);

        var engine = new PreComplianceEngine(new StaticSource([essential, suspicious]), new MixedClassifier());
        var result = engine.Scan();

        Assert.False(result.IsClean);
        Assert.Single(result.SuspiciousProcesses);
        Assert.Equal(suspicious.Name, result.SuspiciousProcesses[0].Name);
    }

    private sealed class StaticSource(IReadOnlyList<ProcessInfo> processes) : IProcessSource
    {
        public IReadOnlyList<ProcessInfo> GetProcesses() => processes;
    }

    private sealed class MixedClassifier : IProcessClassifier
    {
        public ClassificationResult Classify(ProcessInfo process) => process.ProcessId == 1
            ? new(Classification.Allowed, "windows-system", "Windows Infrastructure", "Microsoft", null, "Essential Windows process")
            : new(Classification.Suspicious, "user-app", "Unauthorized Application", null, null, "Suspicious User App");
    }
}
