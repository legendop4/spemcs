using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace Spemcs.Agent.UI.Services;

public interface IStartupService
{
    bool ConfigureStartup(string? exePath = null);
    bool RemoveStartup();
    bool IsConfigured();
}

public class StartupService : IStartupService
{
    private const string TaskName = "SPEMCS Endpoint Agent";
    private const string RegistryKeyName = "SpemcsEndpointAgent";

    public bool ConfigureStartup(string? exePath = null)
    {
        var targetExe = exePath;
        if (string.IsNullOrWhiteSpace(targetExe))
        {
            targetExe = Process.GetCurrentProcess().MainModule?.FileName;
        }

        if (string.IsNullOrWhiteSpace(targetExe) || !File.Exists(targetExe))
        {
            return false;
        }

        var taskCreated = CreateScheduledTask(targetExe);
        if (taskCreated)
        {
            return true;
        }

        // Fallback to registry if schtasks.exe cannot be created
        return SetRegistryRun(targetExe);
    }

    public bool RemoveStartup()
    {
        var taskRemoved = DeleteScheduledTask();
        var regRemoved = RemoveRegistryRun();
        return taskRemoved || regRemoved;
    }

    public bool IsConfigured()
    {
        if (IsScheduledTaskPresent()) return true;
        return IsRegistryRunPresent();
    }

    private static bool CreateScheduledTask(string exePath)
    {
        try
        {
            // Create or replace an on-logon task that runs with highest available privileges
            var args = $"/create /tn \"{TaskName}\" /tr \"\\\"{exePath}\\\"\" /sc onlogon /rl highest /f";
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                proc.WaitForExit(5000);
                return proc.ExitCode == 0;
            }
        }
        catch { }

        return false;
    }

    private static bool DeleteScheduledTask()
    {
        try
        {
            var args = $"/delete /tn \"{TaskName}\" /f";
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                proc.WaitForExit(5000);
                return proc.ExitCode == 0;
            }
        }
        catch { }

        return false;
    }

    private static bool IsScheduledTaskPresent()
    {
        try
        {
            var args = $"/query /tn \"{TaskName}\"";
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                proc.WaitForExit(5000);
                return proc.ExitCode == 0;
            }
        }
        catch { }

        return false;
    }

    private static bool SetRegistryRun(string exePath)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
            if (key != null)
            {
                key.SetValue(RegistryKeyName, $"\"{exePath}\"");
                return true;
            }
        }
        catch { }

        return false;
    }

    private static bool RemoveRegistryRun()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
            if (key != null)
            {
                key.DeleteValue(RegistryKeyName, false);
                return true;
            }
        }
        catch { }

        return false;
    }

    private static bool IsRegistryRunPresent()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false);
            return key?.GetValue(RegistryKeyName) != null;
        }
        catch { }

        return false;
    }
}
