using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Spemcs.Agent.Service;

public interface IUiLauncher
{
    bool HasActiveInteractiveSession();
    bool Launch(string executablePath, string? arguments = null);
}

public sealed class InteractiveSessionUiLauncher : IUiLauncher
{
    private readonly ILogger<InteractiveSessionUiLauncher>? _log;

    public InteractiveSessionUiLauncher(ILogger<InteractiveSessionUiLauncher>? log = null)
    {
        _log = log;
    }

    public bool HasActiveInteractiveSession()
    {
        try
        {
            if (Process.GetCurrentProcess().SessionId != 0)
            {
                return true;
            }

            var session = WTSGetActiveConsoleSessionId();
            if (session != uint.MaxValue && session != 0 && WTSQueryUserToken(session, out var userToken))
            {
                CloseHandle(userToken);
                return true;
            }

            if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var pSessionInfo, out var count))
            {
                try
                {
                    var structSize = Marshal.SizeOf<WTS_SESSION_INFO>();
                    for (int i = 0; i < count; i++)
                    {
                        var ptr = IntPtr.Add(pSessionInfo, i * structSize);
                        var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(ptr);
                        if (info.SessionId > 0 && info.State == WTSActive)
                        {
                            if (WTSQueryUserToken((uint)info.SessionId, out var token))
                            {
                                CloseHandle(token);
                                return true;
                            }
                        }
                    }
                }
                finally
                {
                    WTSFreeMemory(pSessionInfo);
                }
            }
        }
        catch (Exception ex)
        {
            _log?.LogWarning(ex, "Failed to query active interactive session status");
        }
        return false;
    }

    public bool Launch(string executablePath, string? arguments = null)
    {
        var launchArgs = arguments ?? "--exam-mode";
        var isSession0 = Process.GetCurrentProcess().SessionId == 0;
        _log?.LogInformation("[UI_LAUNCH_BEGIN] executablePath={ExecutablePath}, args={Args}, session0={IsSession0}", executablePath, launchArgs, isSession0);

        try
        {
            var consoleSession = WTSGetActiveConsoleSessionId();
            var targetSessionId = uint.MaxValue;
            var userToken = IntPtr.Zero;
            var enumeratedCount = 0;

            if (consoleSession != uint.MaxValue && consoleSession != 0 && WTSQueryUserToken(consoleSession, out userToken))
            {
                targetSessionId = consoleSession;
                _log?.LogInformation("[UI_SESSION_SELECTED] sessionId={SessionId}, sessionState=ActiveConsole", targetSessionId);
                _log?.LogInformation("[UI_TOKEN_ACQUIRED] sessionId={SessionId}", targetSessionId);
            }
            else
            {
                if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var pSessionInfo, out enumeratedCount))
                {
                    _log?.LogInformation("[UI_SESSION_DISCOVERY] activeConsoleSession={ConsoleSession}, enumeratedCount={Count}", consoleSession, enumeratedCount);
                    try
                    {
                        var structSize = Marshal.SizeOf<WTS_SESSION_INFO>();
                        // Pass 1: active user sessions
                        for (int i = 0; i < enumeratedCount; i++)
                        {
                            var ptr = IntPtr.Add(pSessionInfo, i * structSize);
                            var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(ptr);
                            if (info.SessionId > 0 && info.State == WTSActive)
                            {
                                if (WTSQueryUserToken((uint)info.SessionId, out userToken))
                                {
                                    targetSessionId = (uint)info.SessionId;
                                    _log?.LogInformation("[UI_SESSION_SELECTED] sessionId={SessionId}, sessionState=WTSActive", targetSessionId);
                                    _log?.LogInformation("[UI_TOKEN_ACQUIRED] sessionId={SessionId}", targetSessionId);
                                    break;
                                }
                            }
                        }

                        // Pass 2: non-active user sessions fallback (e.g. connected or locked desktop)
                        if (userToken == IntPtr.Zero)
                        {
                            for (int i = 0; i < enumeratedCount; i++)
                            {
                                var ptr = IntPtr.Add(pSessionInfo, i * structSize);
                                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(ptr);
                                if (info.SessionId > 0 && info.State != WTSActive)
                                {
                                    if (WTSQueryUserToken((uint)info.SessionId, out userToken))
                                    {
                                        targetSessionId = (uint)info.SessionId;
                                        _log?.LogInformation("[UI_SESSION_SELECTED] sessionId={SessionId}, sessionState={State}", targetSessionId, info.State);
                                        _log?.LogInformation("[UI_TOKEN_ACQUIRED] sessionId={SessionId}", targetSessionId);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    finally
                    {
                        WTSFreeMemory(pSessionInfo);
                    }
                }
                else
                {
                    var err = Marshal.GetLastWin32Error();
                    var msg = new Win32Exception(err).Message;
                    _log?.LogWarning("WTSEnumerateSessions failed: Win32Error={Error} ({Win32Msg})", err, msg);
                }
            }

            if (userToken != IntPtr.Zero && targetSessionId != uint.MaxValue)
            {
                try
                {
                    // 0x02000000 = MAXIMUM_ALLOWED (0x10000000 GENERIC_ALL fails with ERROR_ACCESS_DENIED on user session tokens)
                    if (DuplicateTokenEx(userToken, 0x02000000, IntPtr.Zero, 2, 1, out var primaryToken))
                    {
                        _log?.LogInformation("[UI_TOKEN_DUPLICATED] sessionId={SessionId}", targetSessionId);
                        try
                        {
                            IntPtr environment = IntPtr.Zero;
                            uint creationFlags = 0;
                            if (CreateEnvironmentBlock(out environment, primaryToken, false) && environment != IntPtr.Zero)
                            {
                                creationFlags |= 0x00000400; // CREATE_UNICODE_ENVIRONMENT
                                _log?.LogInformation("[UI_ENVIRONMENT_CREATED] sessionId={SessionId}", targetSessionId);
                            }
                            else
                            {
                                var err = Marshal.GetLastWin32Error();
                                var msg = new Win32Exception(err).Message;
                                _log?.LogWarning("CreateEnvironmentBlock returned false for Session {SessionId}: Win32Error={Error} ({Win32Msg}). Proceeding with default environment.", targetSessionId, err, msg);
                                environment = IntPtr.Zero;
                            }

                            try
                            {
                                var startup = new StartupInfo
                                {
                                    cb = Marshal.SizeOf<StartupInfo>(),
                                    lpDesktop = @"winsta0\default",
                                    dwFlags = 1,
                                    wShowWindow = 1
                                };
                                var workingDir = Path.GetDirectoryName(executablePath);
                                var command = new StringBuilder($"\"{executablePath}\" {launchArgs}".Trim());

                                _log?.LogInformation("[UI_PROCESS_CREATE_BEGIN] sessionId={SessionId}, executablePath={ExecutablePath}", targetSessionId, executablePath);

                                // Primary attempt: executablePath as lpApplicationName
                                bool created = CreateProcessAsUser(
                                    primaryToken,
                                    executablePath,
                                    command,
                                    IntPtr.Zero,
                                    IntPtr.Zero,
                                    false,
                                    creationFlags,
                                    environment,
                                    workingDir,
                                    ref startup,
                                    out var process);

                                if (!created)
                                {
                                    var err = Marshal.GetLastWin32Error();
                                    var msg = new Win32Exception(err).Message;
                                    _log?.LogWarning("CreateProcessAsUser (attempt 1 with applicationName) failed for Session {SessionId}: Win32Error={Error} ({Win32Msg}). Retrying with lpApplicationName=null...", targetSessionId, err, msg);

                                    // Secondary attempt: lpApplicationName = null
                                    var fullCommand = new StringBuilder($"\"{executablePath}\" {launchArgs}".Trim());
                                    created = CreateProcessAsUser(
                                        primaryToken,
                                        null,
                                        fullCommand,
                                        IntPtr.Zero,
                                        IntPtr.Zero,
                                        false,
                                        creationFlags,
                                        environment,
                                        workingDir,
                                        ref startup,
                                        out process);
                                }

                                if (created)
                                {
                                    _log?.LogInformation("[UI_PROCESS_CREATE_SUCCESS] sessionId={SessionId}, pid={ProcessId}", targetSessionId, process.processId);
                                    CloseHandle(process.hProcess);
                                    CloseHandle(process.hThread);
                                    return true;
                                }
                                else
                                {
                                    var err = Marshal.GetLastWin32Error();
                                    var msg = new Win32Exception(err).Message;
                                    _log?.LogError("[UI_PROCESS_CREATE_FAILED] sessionId={SessionId}, win32Error={Error}, message={Win32Msg}", targetSessionId, err, msg);
                                    _log?.LogError("[UI_LAUNCH_FAILED] reason=CREATE_PROCESS_AS_USER_FAILED");
                                    return false;
                                }
                            }
                            finally
                            {
                                if (environment != IntPtr.Zero)
                                {
                                    DestroyEnvironmentBlock(environment);
                                }
                            }
                        }
                        finally
                        {
                            CloseHandle(primaryToken);
                        }
                    }
                    else
                    {
                        var err = Marshal.GetLastWin32Error();
                        var msg = new Win32Exception(err).Message;
                        _log?.LogError("[UI_PROCESS_CREATE_FAILED] sessionId={SessionId}, win32Error={Error}, message=DuplicateTokenEx failed: {Win32Msg}", targetSessionId, err, msg);
                        _log?.LogError("[UI_LAUNCH_FAILED] reason=DUPLICATE_TOKEN_FAILED");
                        return false;
                    }
                }
                finally
                {
                    CloseHandle(userToken);
                }
            }
        }
        catch (Exception ex)
        {
            _log?.LogError(ex, "InteractiveSessionUiLauncher encountered an error attempting CreateProcessAsUser");
        }

        // Fallback for non-Session 0 execution (e.g. tests or interactive console debugging)
        try
        {
            if (Process.GetCurrentProcess().SessionId != 0)
            {
                _log?.LogInformation("Running in non-Session 0 ({SessionId}); using direct Process.Start fallback for {Path}",
                    Process.GetCurrentProcess().SessionId, executablePath);
                var fallbackProc = Process.Start(new ProcessStartInfo
                {
                    FileName = executablePath,
                    Arguments = launchArgs,
                    UseShellExecute = true,
                    WorkingDirectory = Path.GetDirectoryName(executablePath)
                });
                if (fallbackProc != null)
                {
                    _log?.LogInformation("[UI_PROCESS_CREATE_SUCCESS] sessionId={SessionId}, pid={Pid} (Process.Start fallback)",
                        Process.GetCurrentProcess().SessionId, fallbackProc.Id);
                    return true;
                }
            }
        }
        catch { }

        _log?.LogError("[UI_LAUNCH_FAILED] reason=NO_ACTIVE_INTERACTIVE_SESSION. Cannot launch UI: No active interactive user session available in Session 0. Awaiting user logon.");
        return false;
    }

    private const int WTSActive = 0;

    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version, out IntPtr ppSessionInfo, out int pCount);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr pMemory);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess, IntPtr tokenAttributes, int impersonationLevel, int tokenType, out IntPtr newToken);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
    [DllImport("userenv.dll", SetLastError = true)] private static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessAsUser(IntPtr token, string? applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string? currentDirectory, ref StartupInfo startupInfo, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int processId;
        public int threadId;
    }
}
