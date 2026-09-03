using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class ClassificationTests
{
    [Fact]
    public void Chrome_browser_is_allowed_and_edge_firefox_are_suspicious()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-classifier", Guid.NewGuid().ToString("N"));
        var chromeDir = Path.Combine(root, @"Google\Chrome\Application");
        Directory.CreateDirectory(chromeDir);

        try
        {
            var chromeExe = Path.Combine(chromeDir, "chrome.exe");
            var edgeExe = Path.Combine(root, "msedge.exe");
            var firefoxExe = Path.Combine(root, "firefox.exe");

            File.WriteAllBytes(chromeExe, [1, 2, 3]);
            File.WriteAllBytes(edgeExe, [1, 2, 3]);
            File.WriteAllBytes(firefoxExe, [1, 2, 3]);

            var trust = new FakeTrust(chromeExe);
            var classifier = new ConfigurableProcessClassifier(ApprovedBrowserFamily.Chrome, Path.Combine(root, "agent"), trust, windowsRoot: Path.Combine(root, "windows"));

            var chromeResult = classifier.Classify(new ProcessInfo(10, "chrome", chromeExe, null, true));
            var edgeResult = classifier.Classify(new ProcessInfo(11, "msedge", edgeExe, null, true));
            var firefoxResult = classifier.Classify(new ProcessInfo(12, "firefox", firefoxExe, null, true));

            Assert.Equal(Classification.Allowed, chromeResult.Classification);
            Assert.Equal(Classification.Suspicious, edgeResult.Classification);
            Assert.Equal(Classification.Suspicious, firefoxResult.Classification);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Windows_system_processes_are_allowed()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-system", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var systemFile = Path.Combine(root, "svchost.exe");
            File.WriteAllBytes(systemFile, [9]);

            var classifier = new ConfigurableProcessClassifier(selfRoot: Path.Combine(root, "agent"), windowsRoot: root, trust: new FakeTrust(systemFile));
            var result = classifier.Classify(new ProcessInfo(1, "svchost", systemFile, null, false));

            Assert.Equal(Classification.Allowed, result.Classification);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    private sealed class FakeTrust(params string[] trustedPaths) : IFileTrustVerifier
    {
        private readonly HashSet<string> _trusted = new(trustedPaths, StringComparer.OrdinalIgnoreCase);
        public bool Valid = true;

        public FileTrustResult Verify(string path) => new(Valid && _trusted.Contains(path), Valid ? "Google LLC" : null, Valid ? "test-valid" : "test-invalid");
    }
}
