using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Spemcs.Agent.Service;

public interface IUiLauncher { void Launch(string executablePath); }

public sealed class InteractiveSessionUiLauncher : IUiLauncher
{
    public void Launch(string executablePath)
    {
        try
        {
            var session = WTSGetActiveConsoleSessionId();
            if (session != uint.MaxValue && WTSQueryUserToken(session, out var userToken))
            {
                try
                {
                    if (DuplicateTokenEx(userToken, 0x10000000, IntPtr.Zero, 2, 1, out var primaryToken))
                    {
                        try
                        {
                            if (CreateEnvironmentBlock(out var environment, primaryToken, false))
                            {
                                try
                                {
                                    var startup = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>(), lpDesktop = "winsta0\\default" };
                                    var command = new StringBuilder($"\"{executablePath}\"");
                                    if (CreateProcessAsUser(primaryToken, null, command, IntPtr.Zero, IntPtr.Zero, false, 0x00000400 | 0x00000010, environment, Path.GetDirectoryName(executablePath), ref startup, out var process))
                                    {
                                        CloseHandle(process.hProcess);
                                        CloseHandle(process.hThread);
                                        return;
                                    }
                                }
                                finally { DestroyEnvironmentBlock(environment); }
                            }
                        }
                        finally { CloseHandle(primaryToken); }
                    }
                }
                finally { CloseHandle(userToken); }
            }
        }
        catch
        {
            // Fallback to direct process launch when running outside LocalSystem service context
        }

        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(executablePath)
        });
    }
    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess, IntPtr tokenAttributes, int impersonationLevel, int tokenType, out IntPtr newToken);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessAsUser(IntPtr token, string? applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string? currentDirectory, ref StartupInfo startupInfo, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfo { public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { public IntPtr hProcess; public IntPtr hThread; public int processId; public int threadId; }
}
