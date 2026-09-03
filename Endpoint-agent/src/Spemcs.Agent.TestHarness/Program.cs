using System;
using System.IO;
using System.Linq;
using Spemcs.Agent.Core;
using Spemcs.Agent.Ipc;
using Spemcs.Agent.TestHarness;

var uiExeCandidates = new[]
{
    Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Spemcs.Agent.UI", "bin", "Debug", "net8.0-windows", "Spemcs.Agent.UI.exe")),
    Path.Combine(AppContext.BaseDirectory, "Spemcs.Agent.UI.exe")
};
var uiExe = uiExeCandidates.FirstOrDefault(File.Exists);
if (uiExe != null)
{
    Console.WriteLine($"Launching SPEMCS Unified Examination Shield & UI from {uiExe}...");
    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
    {
        FileName = uiExe,
        UseShellExecute = true,
        WorkingDirectory = Path.GetDirectoryName(uiExe)
    });
    Console.WriteLine("SPEMCS Examination Agent UI started successfully.");
    return;
}

Console.WriteLine("SPEMCS UI binary not found. Please build with 'dotnet build Endpoint-agent\\Spemcs.Agent.sln'.");
