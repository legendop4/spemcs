using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Implements IFirewallAdapter using the Windows Defender Firewall COM interface (INetFwPolicy2).
/// </summary>
public sealed class WindowsFirewallAdapter : IFirewallAdapter
{
    private readonly Type _policyType;
    private readonly Type _ruleType;
    private readonly ILogger<WindowsFirewallAdapter> _logger;

    public WindowsFirewallAdapter(ILogger<WindowsFirewallAdapter>? logger = null)
    {
        _logger = logger ?? NullLogger<WindowsFirewallAdapter>.Instance;
        _policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)
                      ?? throw new PlatformNotSupportedException("HNetCfg.FwPolicy2 COM class not found.");
        _ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)
                    ?? throw new PlatformNotSupportedException("HNetCfg.FWRule COM class not found.");
    }

    private dynamic CreatePolicyInstance() => Activator.CreateInstance(_policyType)!;
    private dynamic CreateRuleInstance() => Activator.CreateInstance(_ruleType)!;

    public FirewallProfileBaseline GetBaseline()
    {
        dynamic policy = CreatePolicyInstance();
        var currentProfiles = (FirewallProfiles)(int)policy.CurrentProfileTypes;

        var domainAction = (FirewallAction)(int)policy.DefaultOutboundAction((int)FirewallProfiles.Domain);
        var privateAction = (FirewallAction)(int)policy.DefaultOutboundAction((int)FirewallProfiles.Private);
        var publicAction = (FirewallAction)(int)policy.DefaultOutboundAction((int)FirewallProfiles.Public);

        return new FirewallProfileBaseline(
            DomainDefaultOutbound: domainAction,
            PrivateDefaultOutbound: privateAction,
            PublicDefaultOutbound: publicAction,
            ActiveProfiles: currentProfiles,
            CapturedUtc: DateTimeOffset.UtcNow
        );
    }

    public void SetDefaultOutboundAction(FirewallProfiles profile, FirewallAction action)
    {
        object policy = CreatePolicyInstance();
        int actionInt = (int)action;

        void SetAction(FirewallProfiles p)
        {
            try
            {
                policy.GetType().InvokeMember(
                    "DefaultOutboundAction",
                    System.Reflection.BindingFlags.SetProperty,
                    null,
                    policy,
                    new object[] { (int)p, actionInt });
            }
            catch (System.Reflection.TargetInvocationException tie) when (tie.InnerException != null)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(tie.InnerException).Throw();
            }
        }

        if (profile.HasFlag(FirewallProfiles.Domain))
        {
            SetAction(FirewallProfiles.Domain);
        }
        if (profile.HasFlag(FirewallProfiles.Private))
        {
            SetAction(FirewallProfiles.Private);
        }
        if (profile.HasFlag(FirewallProfiles.Public))
        {
            SetAction(FirewallProfiles.Public);
        }
    }

    public void AddRule(FirewallRuleModel rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        _logger.LogInformation(
            "WindowsFirewallAdapter.AddRule: Preparing COM rule '{Name}' [Grouping='{Grouping}', Enabled={Enabled}, Direction={Direction}, Action={Action}, Protocol={Protocol}, Profiles={Profiles}, LocalAddresses='{LocalAddresses}', RemoteAddresses='{RemoteAddresses}', LocalPorts='{LocalPorts}', RemotePorts='{RemotePorts}', ApplicationName='{ApplicationName}', ServiceName='{ServiceName}']",
            rule.Name,
            rule.Group,
            rule.Enabled,
            rule.Direction,
            rule.Action,
            rule.Protocol,
            rule.Profiles,
            rule.LocalAddresses,
            rule.RemoteAddresses,
            rule.LocalPorts,
            rule.RemotePorts,
            rule.ApplicationPath ?? "none",
            rule.ServiceName ?? "none"
        );

        dynamic policy = CreatePolicyInstance();
        dynamic fwRule = CreateRuleInstance();

        try
        {
            fwRule.Name = rule.Name;
            fwRule.Description = $"SPEMCS Exam Lockdown Rule: {rule.Purpose}";
            fwRule.Grouping = rule.Group;
            fwRule.Direction = (int)rule.Direction;
            fwRule.Action = (int)rule.Action;
            fwRule.Protocol = (int)rule.Protocol;

            if (!string.IsNullOrWhiteSpace(rule.LocalPorts) && rule.LocalPorts != "*")
            {
                fwRule.LocalPorts = rule.LocalPorts;
            }

            if (!string.IsNullOrWhiteSpace(rule.RemotePorts) && rule.RemotePorts != "*")
            {
                fwRule.RemotePorts = rule.RemotePorts;
            }

            if (!string.IsNullOrWhiteSpace(rule.RemoteAddresses) && rule.RemoteAddresses != "*")
            {
                fwRule.RemoteAddresses = rule.RemoteAddresses;
            }

            if (!string.IsNullOrWhiteSpace(rule.LocalAddresses) && rule.LocalAddresses != "*")
            {
                fwRule.LocalAddresses = rule.LocalAddresses;
            }

            if (!string.IsNullOrWhiteSpace(rule.ApplicationPath))
            {
                fwRule.ApplicationName = rule.ApplicationPath;
            }

            // Diagnostic Requirement 3: Never assign ServiceName unless rule.ServiceName is non-null, non-empty, and valid
            if (!string.IsNullOrWhiteSpace(rule.ServiceName) &&
                !string.Equals(rule.ServiceName, "none", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(rule.ServiceName, "*", StringComparison.OrdinalIgnoreCase))
            {
                fwRule.ServiceName = rule.ServiceName;
            }

            fwRule.Profiles = (int)rule.Profiles;
            fwRule.Enabled = rule.Enabled;

            policy.Rules.Add(fwRule);
            _logger.LogInformation("WindowsFirewallAdapter.AddRule: Successfully added rule '{Name}'", rule.Name);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WindowsFirewallAdapter.AddRule: FAILED on rule '{Name}' with error: {Message}", rule.Name, ex.Message);
            throw;
        }
    }

    public bool RemoveRule(string ruleName)
    {
        dynamic policy = CreatePolicyInstance();
        try
        {
            policy.Rules.Remove(ruleName);
            return true;
        }
        catch (COMException)
        {
            return false;
        }
        catch (System.IO.FileNotFoundException)
        {
            return false;
        }
    }

    public bool RuleExists(string ruleName)
    {
        dynamic policy = CreatePolicyInstance();
        try
        {
            dynamic rule = policy.Rules.Item(ruleName);
            return rule != null;
        }
        catch (COMException)
        {
            return false;
        }
        catch (System.IO.FileNotFoundException)
        {
            return false;
        }
    }

    public IReadOnlyList<string> GetRuleNamesByGroup(string group)
    {
        dynamic policy = CreatePolicyInstance();
        var list = new List<string>();

        foreach (dynamic r in policy.Rules)
        {
            try
            {
                string? g = r.Grouping;
                if (string.Equals(g, group, StringComparison.OrdinalIgnoreCase))
                {
                    string name = r.Name;
                    list.Add(name);
                }
            }
            catch
            {
                // Continue enumerating if individual rule cannot be inspected
            }
        }

        return list;
    }

    public IReadOnlyList<FirewallRuleModel> GetRulesByGroup(string group)
    {
        dynamic policy = CreatePolicyInstance();
        var list = new List<FirewallRuleModel>();

        foreach (dynamic r in policy.Rules)
        {
            try
            {
                string? g = r.Grouping;
                if (string.Equals(g, group, StringComparison.OrdinalIgnoreCase))
                {
                    string name = r.Name;
                    int direction = (int)r.Direction;
                    int action = (int)r.Action;
                    int protocol = (int)r.Protocol;
                    string localPorts = r.LocalPorts ?? "*";
                    string remotePorts = r.RemotePorts ?? "*";
                    string remoteAddresses = r.RemoteAddresses ?? "*";
                    string localAddresses = r.LocalAddresses ?? "*";
                    string? appPath = r.ApplicationName;
                    string? serviceName = null;
                    try { serviceName = r.ServiceName; } catch { }
                    int profiles = (int)r.Profiles;
                    bool enabled = (bool)r.Enabled;

                    list.Add(new FirewallRuleModel(
                        Name: name,
                        Group: group,
                        Direction: (FirewallDirection)direction,
                        Action: (FirewallAction)action,
                        Protocol: (FirewallProtocol)protocol,
                        LocalPorts: localPorts,
                        RemotePorts: remotePorts,
                        RemoteAddresses: remoteAddresses,
                        LocalAddresses: localAddresses,
                        ApplicationPath: appPath,
                        Profiles: (FirewallProfiles)profiles,
                        Enabled: enabled,
                        Purpose: "Discovered",
                        SessionId: Guid.Empty,
                        ServiceName: serviceName
                    ));
                }
            }
            catch
            {
                // Ignore read errors on malformed rules
            }
        }

        return list;
    }
}
