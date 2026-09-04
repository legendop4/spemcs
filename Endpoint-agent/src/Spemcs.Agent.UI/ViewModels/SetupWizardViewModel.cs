using System;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Input;
using Spemcs.Agent.UI.Models;
using Spemcs.Agent.UI.Services;

namespace Spemcs.Agent.UI.ViewModels;

public class SetupWizardViewModel : ViewModelBase
{
    private readonly ICentralApiClient _apiClient;
    private readonly IAgentConfigService _configService;
    private readonly IStartupService _startupService;

    private string _serverUrl = "http://127.0.0.1:8001";
    private LabDto? _selectedLab;
    private string _pcNumber = "01";
    private string _workstationIdentifier = string.Empty;
    private string _statusMessage = "Enter Central Server URL and select your Lab.";
    private bool _isError;
    private bool _isSuccess;
    private bool _isBusy;
    private bool _canProceed;

    public ObservableCollection<LabDto> Labs { get; } = new();

    public string ServerUrl
    {
        get => _serverUrl;
        set
        {
            if (SetProperty(ref _serverUrl, value))
            {
                UpdateWorkstationIdentifier();
            }
        }
    }

    public LabDto? SelectedLab
    {
        get => _selectedLab;
        set
        {
            if (SetProperty(ref _selectedLab, value))
            {
                UpdateWorkstationIdentifier();
            }
        }
    }

    public string PcNumber
    {
        get => _pcNumber;
        set
        {
            if (SetProperty(ref _pcNumber, value))
            {
                UpdateWorkstationIdentifier();
            }
        }
    }

    public string WorkstationIdentifier
    {
        get => _workstationIdentifier;
        private set => SetProperty(ref _workstationIdentifier, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public bool IsError
    {
        get => _isError;
        set => SetProperty(ref _isError, value);
    }

    public bool IsSuccess
    {
        get => _isSuccess;
        set => SetProperty(ref _isSuccess, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set { if (SetProperty(ref _isBusy, value)) System.Windows.Input.CommandManager.InvalidateRequerySuggested(); }
    }

    public bool CanProceed
    {
        get => _canProceed;
        set { if (SetProperty(ref _canProceed, value)) System.Windows.Input.CommandManager.InvalidateRequerySuggested(); }
    }

    public ICommand FetchLabsCommand { get; }
    public ICommand RegisterCommand { get; }

    public Action? OnRegistrationCompleted { get; set; }

    public SetupWizardViewModel(
        ICentralApiClient? apiClient = null,
        IAgentConfigService? configService = null,
        IStartupService? startupService = null)
    {
        _apiClient = apiClient ?? new CentralApiClient();
        _configService = configService ?? new AgentConfigService();
        _startupService = startupService ?? new StartupService();

        FetchLabsCommand = new RelayCommand(async () => await FetchLabsAsync(), () => !IsBusy);
        RegisterCommand = new RelayCommand(async () => await RegisterAsync(), () => CanRegister());

        // Load existing config if present
        var existing = _configService.Load();
        if (existing != null)
        {
            if (!string.IsNullOrWhiteSpace(existing.ServerUrl)) _serverUrl = existing.ServerUrl;
            if (!string.IsNullOrWhiteSpace(existing.PcNumber)) _pcNumber = existing.PcNumber;
        }

        UpdateWorkstationIdentifier();
    }

    public async Task InitializeAsync()
    {
        await FetchLabsAsync();
    }

    private void UpdateWorkstationIdentifier()
    {
        var labClean = SelectedLab != null
            ? Regex.Replace(SelectedLab.LabName, @"\s+", "")
            : "Lab";

        var pcClean = (PcNumber ?? string.Empty).Trim();
        if (pcClean.StartsWith("PC-", StringComparison.OrdinalIgnoreCase))
        {
            WorkstationIdentifier = $"{labClean}-{pcClean.ToUpperInvariant()}";
        }
        else if (int.TryParse(pcClean, out var num))
        {
            WorkstationIdentifier = $"{labClean}-PC{num:D2}";
        }
        else if (!string.IsNullOrWhiteSpace(pcClean))
        {
            WorkstationIdentifier = $"{labClean}-{pcClean}";
        }
        else
        {
            WorkstationIdentifier = $"{labClean}-PC01";
        }

        CanProceed = CanRegister();
    }

    public bool CanRegister()
    {
        return !IsBusy &&
               !string.IsNullOrWhiteSpace(ServerUrl) &&
               SelectedLab != null &&
               !string.IsNullOrWhiteSpace(PcNumber);
    }

    public async Task FetchLabsAsync()
    {
        if (string.IsNullOrWhiteSpace(ServerUrl))
        {
            SetStatus("Please enter a valid Central Server URL.", isError: true);
            return;
        }

        IsBusy = true;
        SetStatus("Connecting to Central Server and fetching labs...", isError: false);

        try
        {
            var labsList = await _apiClient.FetchLabsAsync(ServerUrl);
            Labs.Clear();

            foreach (var lab in labsList)
            {
                Labs.Add(lab);
            }

            if (Labs.Count > 0)
            {
                SelectedLab = Labs[0];
                SetStatus($"Successfully loaded {Labs.Count} labs from Central Server.", isError: false, isSuccess: true);
            }
            else
            {
                SetStatus("Connected to Central Server, but no examination labs were returned.", isError: true);
            }
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, isError: true);
        }
        finally
        {
            IsBusy = false;
            UpdateWorkstationIdentifier();
        }
    }

    public async Task RegisterAsync()
    {
        if (!CanRegister() || SelectedLab == null) return;

        IsBusy = true;
        SetStatus($"Registering workstation '{WorkstationIdentifier}' with Central Server...", isError: false);

        try
        {
            var localIp = GetLocalIpAddress();
            var hostname = Environment.MachineName;
            var hwUuid = WorkstationIdentifier; // Use authoritative identifier

            var req = new DeviceRegistrationRequest
            {
                DeviceName = WorkstationIdentifier,
                IpAddress = localIp,
                HardwareUuid = hwUuid,
                LabId = SelectedLab.LabId.ToString(),
                PcNumber = PcNumber.Trim(),
                Hostname = hostname
            };

            var res = await _apiClient.RegisterDeviceAsync(ServerUrl, req);

            // Persist configuration locally
            var config = new AgentConfig
            {
                ServerUrl = ServerUrl.Trim().TrimEnd('/'),
                DeviceId = res.DeviceId,
                DeviceName = res.DeviceName,
                HardwareUuid = res.HardwareUuid ?? hwUuid,
                DeviceToken = res.DeviceToken,
                LabId = SelectedLab.LabId.ToString(),
                LabCode = SelectedLab.BuildingId,
                LabName = SelectedLab.LabName,
                BuildingName = SelectedLab.BuildingId,
                PcNumber = res.PcNumber ?? PcNumber.Trim(),
                Registered = true,
                RegisteredAtUtc = DateTimeOffset.UtcNow
            };

            _configService.Save(config);

            // Configure automatic startup on Windows boot
            _startupService.ConfigureStartup();

            SetStatus($"Workstation registered successfully as '{res.DeviceName}'. Launching agent...", isError: false, isSuccess: true);

            await Task.Delay(1000);
            OnRegistrationCompleted?.Invoke();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, isError: true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void SetStatus(string message, bool isError = false, bool isSuccess = false)
    {
        StatusMessage = message;
        IsError = isError;
        IsSuccess = isSuccess;
    }

    private static string GetLocalIpAddress()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
            socket.Connect("8.8.8.8", 65530);
            if (socket.LocalEndPoint is IPEndPoint endPoint)
                return endPoint.Address.ToString();
        }
        catch { }

        return "127.0.0.1";
    }
}
