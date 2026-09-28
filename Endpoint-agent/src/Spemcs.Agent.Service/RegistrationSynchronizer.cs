using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;

namespace Spemcs.Agent.Service;

public interface IRegistrationSynchronizer
{
    Task<bool> SyncRegistrationAsync(string source, bool allowBackendQuery = true, CancellationToken ct = default);
    Task<bool> EnsureAuthoritativeRegistrationAsync(string source, TimeSpan timeout, CancellationToken ct = default);
    bool TrySyncFromConfig(string source);
}

public sealed class RegistrationSynchronizer : IRegistrationSynchronizer
{
    private readonly ILogger<RegistrationSynchronizer> _log;
    private readonly IAgentStore _store;
    private readonly DeviceCredentialStore? _credentials;
    private readonly IRegistrationService? _regService;
    private readonly string _configPath;
    private readonly object _syncLock = new();

    public RegistrationSynchronizer(
        ILogger<RegistrationSynchronizer> log,
        IAgentStore store,
        DeviceCredentialStore? credentials = null,
        IRegistrationService? regService = null,
        string? configPath = null)
    {
        _log = log;
        _store = store;
        _credentials = credentials;
        _regService = regService;
        _configPath = configPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Spemcs", "Endpoint Agent", "config.json");
    }

    public async Task<bool> SyncRegistrationAsync(string source, bool allowBackendQuery = true, CancellationToken ct = default)
    {
        _log.LogInformation("[REGISTRATION_SYNC_START] source={Source}, pid={Pid}", source, Environment.ProcessId);

        if (!File.Exists(_configPath))
        {
            var snap = _store.LoadSnapshot().Registration;
            bool snapPresent = snap != null && snap.DeviceId != Guid.Empty;
            _log.LogInformation("[REGISTRATION_SYNC_FAILED] source={Source}, reason=CONFIG_NOT_FOUND, path={Path}, hasSnapshot={HasSnap}",
                source, _configPath, snapPresent);
            return snapPresent;
        }

        string? serverUrl = null;
        string? hardwareUuid = null;
        string? deviceName = null;
        string? deviceToken = null;
        string? deviceIdStr = null;
        bool isRegistered = false;

        try
        {
            for (int retry = 0; retry < 3; retry++)
            {
                try
                {
                    using var stream = new FileStream(_configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var doc = JsonDocument.Parse(stream);
                    var root = doc.RootElement;

                    if (root.TryGetProperty("registered", out var regProp))
                    {
                        if (regProp.ValueKind == JsonValueKind.True) isRegistered = true;
                        else if (regProp.ValueKind == JsonValueKind.String && bool.TryParse(regProp.GetString(), out var rb)) isRegistered = rb;
                    }

                    serverUrl = root.TryGetProperty("serverUrl", out var sProp) ? sProp.GetString()?.Trim() : null;
                    hardwareUuid = root.TryGetProperty("hardwareUuid", out var hProp) ? hProp.GetString()?.Trim() : null;
                    deviceName = root.TryGetProperty("deviceName", out var dProp) ? dProp.GetString()?.Trim() : null;
                    deviceToken = root.TryGetProperty("deviceToken", out var tProp) ? tProp.GetString()?.Trim() : null;
                    deviceIdStr = root.TryGetProperty("deviceId", out var diProp) ? diProp.GetString()?.Trim() : null;
                    break;
                }
                catch (IOException) when (retry < 2)
                {
                    await Task.Delay(100, ct).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[REGISTRATION_SYNC_FAILED] source={Source}, reason=CONFIG_PARSE_ERROR", source);
            return false;
        }

        bool hasDevId = Guid.TryParse(deviceIdStr, out var parsedDevId) && parsedDevId != Guid.Empty;
        bool hasHwUuid = !string.IsNullOrWhiteSpace(hardwareUuid);
        bool hasToken = !string.IsNullOrWhiteSpace(deviceToken);
        bool hasDevName = !string.IsNullOrWhiteSpace(deviceName);
        bool hasServerUrl = !string.IsNullOrWhiteSpace(serverUrl);
        var existingSnapshot = _store.LoadSnapshot().Registration;
        bool hasSnapshot = existingSnapshot != null && existingSnapshot.DeviceId != Guid.Empty;

        _log.LogInformation("[REGISTRATION_SOURCE] source={Source}, hasDeviceId={HasDevId}, hasHardwareUuid={HasHwUuid}, hasDeviceToken={HasToken}, isRegistered={IsReg}, hasSnapshot={HasSnap}",
            source, hasDevId, hasHwUuid, hasToken, isRegistered, hasSnapshot);

        // Path A: Local config has authoritative deviceId and is registered
        if (hasDevId && isRegistered && hasDevName)
        {
            _log.LogInformation("[REGISTRATION_VALIDATED] source={Source}, deviceIdPresent=true, hardwareUuidPresent={HasHwUuid}, serverUrlPresent={HasServerUrl}",
                source, hasHwUuid, hasServerUrl);

            lock (_syncLock)
            {
                var cur = _store.LoadSnapshot().Registration;
                if (cur == null || cur.DeviceId != parsedDevId || cur.DeviceName != deviceName)
                {
                    _store.SaveRegistration(new DeviceRegistration(parsedDevId, deviceName!, GetCurrentIpAddress(), DateTimeOffset.UtcNow));
                    _log.LogInformation("[REGISTRATION_SAVED] source={Source}, deviceName={Name}, deviceIdPresent=true", source, deviceName);
                }
                else
                {
                    _log.LogInformation("[REGISTRATION_SAVED] source={Source}, idempotent=true, deviceName={Name}, deviceIdPresent=true", source, deviceName);
                }
            }

            if (hasToken && _credentials != null && string.IsNullOrWhiteSpace(_credentials.DeviceToken))
            {
                _credentials.SetDeviceToken(deviceToken);
            }

            var verified = _store.LoadSnapshot().Registration;
            bool success = verified != null && verified.DeviceId == parsedDevId;
            _log.LogInformation("[REGISTRATION_VERIFY] source={Source}, success={Success}, deviceIdPresent={DevIdPresent}, hasSnapshot={HasSnap}",
                source, success, verified?.DeviceId != Guid.Empty, verified != null);
            return success;
        }

        // Path B: Missing deviceId in config, but device has registered flag and credentials -> query authoritative backend
        if (!hasDevId && isRegistered && hasDevName && allowBackendQuery && _regService != null)
        {
            _log.LogInformation("[REGISTRATION_SOURCE] source={Source}_backend_query, querying backend for authoritative registration of '{Name}'", source, deviceName);
            try
            {
                using var backendCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                backendCts.CancelAfter(TimeSpan.FromSeconds(5));
                var backendReg = await _regService.RegisterDeviceAsync(deviceName!, GetCurrentIpAddress(), backendCts.Token).ConfigureAwait(false);
                if (backendReg != null && backendReg.DeviceId != Guid.Empty)
                {
                    _log.LogInformation("[REGISTRATION_VALIDATED] source=backend, deviceIdPresent=true, hardwareUuidPresent={HasHwUuid}", hasHwUuid);
                    lock (_syncLock)
                    {
                        _store.SaveRegistration(backendReg);
                    }
                    _log.LogInformation("[REGISTRATION_SAVED] source=backend, deviceName={Name}, deviceIdPresent=true", backendReg.DeviceName);

                    // Persist authoritative deviceId back into config.json for future offline startup
                    TryPersistDeviceIdToConfig(backendReg.DeviceId);

                    var verified = _store.LoadSnapshot().Registration;
                    bool success = verified != null && verified.DeviceId == backendReg.DeviceId;
                    _log.LogInformation("[REGISTRATION_VERIFY] source={Source}, success={Success}, deviceIdPresent=true, hasSnapshot={HasSnap}",
                        source, success, verified != null);
                    return success;
                }
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "[REGISTRATION_SYNC_FAILED] source={Source}, backend query failed", source);
            }
        }

        _log.LogWarning("[REGISTRATION_SYNC_FAILED] source={Source}, reason=UNREGISTERED_OR_MISSING_ID, deviceIdPresent={HasDevId}, hardwareUuidPresent={HasHwUuid}, hasSnapshot={HasSnap}",
            source, hasDevId, hasHwUuid, hasSnapshot);
        return false;
    }

    public async Task<bool> EnsureAuthoritativeRegistrationAsync(string source, TimeSpan timeout, CancellationToken ct = default)
    {
        var snap = _store.LoadSnapshot().Registration;
        if (snap != null && snap.DeviceId != Guid.Empty)
        {
            return true;
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        while (!cts.IsCancellationRequested)
        {
            var success = await SyncRegistrationAsync(source, allowBackendQuery: true, cts.Token).ConfigureAwait(false);
            if (success)
            {
                var verified = _store.LoadSnapshot().Registration;
                if (verified != null && verified.DeviceId != Guid.Empty)
                {
                    return true;
                }
            }

            try
            {
                await Task.Delay(300, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        var finalSnap = _store.LoadSnapshot().Registration;
        return finalSnap != null && finalSnap.DeviceId != Guid.Empty;
    }

    public bool TrySyncFromConfig(string source)
    {
        _log.LogInformation("[REGISTRATION_SYNC_START] source={Source}_sync, pid={Pid}", source, Environment.ProcessId);

        if (!File.Exists(_configPath))
        {
            var snap = _store.LoadSnapshot().Registration;
            return snap != null && snap.DeviceId != Guid.Empty;
        }

        try
        {
            using var stream = new FileStream(_configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var doc = JsonDocument.Parse(stream);
            var root = doc.RootElement;

            bool isReg = false;
            if (root.TryGetProperty("registered", out var regProp))
            {
                if (regProp.ValueKind == JsonValueKind.True) isReg = true;
                else if (regProp.ValueKind == JsonValueKind.String && bool.TryParse(regProp.GetString(), out var rb)) isReg = rb;
            }

            var devName = root.TryGetProperty("deviceName", out var dProp) ? dProp.GetString()?.Trim() : null;
            var devIdStr = root.TryGetProperty("deviceId", out var diProp) ? diProp.GetString()?.Trim() : null;
            var devToken = root.TryGetProperty("deviceToken", out var tProp) ? tProp.GetString()?.Trim() : null;

            bool hasDevId = Guid.TryParse(devIdStr, out var parsedDevId) && parsedDevId != Guid.Empty;
            bool hasDevToken = !string.IsNullOrWhiteSpace(devToken);
            bool isEnrolled = isReg && !string.IsNullOrWhiteSpace(devName) && hasDevId && hasDevToken;

            _log.LogInformation("[REGISTRATION_SOURCE] source={Source}, hasDeviceId={HasDevId}, hasDeviceToken={HasToken}, isRegistered={IsReg}",
                source, hasDevId, hasDevToken, isReg);

            if (isEnrolled)
            {
                lock (_syncLock)
                {
                    var currentReg = _store.LoadSnapshot().Registration;
                    if (currentReg == null || currentReg.DeviceId != parsedDevId || currentReg.DeviceName != devName)
                    {
                        _store.SaveRegistration(new DeviceRegistration(parsedDevId, devName!, GetCurrentIpAddress(), DateTimeOffset.UtcNow));
                        _log.LogInformation("[REGISTRATION_SAVED] source={Source}, deviceName={Name}, deviceIdPresent=true", source, devName);
                    }
                }
                if (_credentials != null && string.IsNullOrWhiteSpace(_credentials.DeviceToken))
                {
                    _credentials.SetDeviceToken(devToken);
                }
                return true;
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "[REGISTRATION_SYNC_FAILED] source={Source}, synchronous evaluation error", source);
        }

        return false;
    }

    private void TryPersistDeviceIdToConfig(Guid deviceId)
    {
        try
        {
            if (!File.Exists(_configPath)) return;
            var text = File.ReadAllText(_configPath);
            using var doc = JsonDocument.Parse(text);
            var dict = new Dictionary<string, object?>();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.NameEquals("deviceId"))
                {
                    dict["deviceId"] = deviceId.ToString();
                }
                else
                {
                    dict[prop.Name] = prop.Value.Clone();
                }
            }
            if (!dict.ContainsKey("deviceId"))
            {
                dict["deviceId"] = deviceId.ToString();
            }

            var json = JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = true });
            var tmp = _configPath + ".tmp." + Guid.NewGuid().ToString("N");
            File.WriteAllText(tmp, json);
            File.Replace(tmp, _configPath, null);
            _log.LogInformation("[REGISTRATION_SAVED] Persisted authoritative deviceId into config.json: {DeviceId}", deviceId);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to persist authoritative deviceId back to config.json");
        }
    }

    private static string GetCurrentIpAddress() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Select(a => a.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))?.ToString() ?? "127.0.0.1";
}
