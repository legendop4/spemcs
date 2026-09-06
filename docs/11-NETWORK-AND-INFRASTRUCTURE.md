# 11. Network Architecture, Windows Firewall & DNS Enforcement

---

## What Am I Looking At?

![Network Topology & Port Matrix](diagrams/11-network-topology.svg)

This document is the deep technical guide to SPEMCS **network enforcement, Windows Firewall COM automation, and DNS lockdown architecture**. It describes how the endpoint agent confines network traffic, blocks tunneling protocols, and suppresses browser-level DNS bypasses.

---

## Why Does It Exist?

Traditional endpoint software attempts to inspect network packets in user-space or install virtual network adapter drivers (TUN/TAP). This approach has severe drawbacks in university environments:
- Installing third-party network filter drivers requires rebooting machines and frequently triggers blue screens (BSOD) or conflicts with campus antivirus software.
- User-space proxy applications (e.g. setting an HTTP proxy) are trivially bypassed by students running CLI tools, Python scripts, or custom VPN executables that ignore system proxy settings.

### The SPEMCS Approach: Native Windows Filtering Platform (WFP)
SPEMCS operates directly at the Windows kernel firewall level using the native **`HNetCfg.FwPolicy2` COM interface**. It does not install external kernel drivers. It leverages the operating system's built-in packet filtering engine to enforce an unbypassable, kernel-level outbound deny policy.

---

## What Happens Internally?

### 1. The Outbound Deny-by-Default Architecture
Unlike standard security configurations that allow outbound traffic and block inbound connections, SPEMCS implements **Outbound Deny-by-Default**:

```
[ Workstation Outbound Traffic ]
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│             Windows Firewall Filtering Engine               │
│  DefaultOutboundAction = NET_FW_ACTION_BLOCK (All Profiles) │
└─────────────────────────────────────────────────────────────┘
       │                                       │
       ▼ Matches Explicit Allow Rule           ▼ No Rule Match
┌──────────────────────────────┐       ┌──────────────────────┐
│  • Approved Browser Binary   │       │  • Python / Curl     │
│  • Target: Exam Vendor CIDR  │       │  • AnyDesk / Discord │
│  • Target: Management Server │       │  • Cloud AI Services │
│                              │       │                      │
│        [ ALLOWED ]           │       │   [ KERNEL DROP ]    │
└──────────────────────────────┘       └──────────────────────┘
```

### 2. Profile Coverage: `FirewallProfiles.All = 7`
The Windows Firewall maintains three separate network profile types:
- `NET_FW_PROFILE2_DOMAIN` (Value: 1)
- `NET_FW_PROFILE2_PRIVATE` (Value: 2)
- `NET_FW_PROFILE2_PUBLIC` (Value: 4)

SPEMCS applies the default outbound block to the bitwise OR of all three profiles:
```csharp
// WindowsFirewallAdapter.cs
public void SetDefaultOutboundAction(FirewallProfiles profiles, FirewallAction action)
{
    // profiles = FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public (7)
    _policy.set_DefaultOutboundAction(profileType, NET_FW_ACTION_BLOCK);
}
```
This guarantees that regardless of whether a student machine is domain-joined, connected to an unauthenticated lab switch, or roaming on a public WiFi subnet, the firewall remains strictly locked.

---

## Browser-Path Scoping & Dynamic Rule Generation

Every dynamic allow rule created by SPEMCS is explicitly bound to the **absolute binary path of the approved browser**:

```csharp
// Rule naming convention: SPEMCS-{sessionId:N}-{ruleSuffix}
var rule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule")!);
rule.Name = $"SPEMCS-{sessionId:N}-VendorAllow";
rule.Description = "SPEMCS active examination vendor platform allow rule";
rule.ApplicationName = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
rule.RemoteAddresses = "198.51.100.0/24,203.0.113.5";
rule.Protocol = (int)NET_FW_IP_PROTOCOL_TCP;
rule.Direction = NET_FW_RULE_DIR_OUT;
rule.Action = NET_FW_ACTION_ALLOW;
rule.Enabled = true;
_rules.Add(rule);
```

### Why Binary Scoping Is Critical:
Even if a student discovers the IP address of the exam server and attempts to connect using Python, PowerShell, or `curl`, the packet is dropped at the kernel level because the calling executable does not match `C:\Program Files\Google\Chrome\Application\chrome.exe`.

---

## DNS Architecture & DoH Registry Suppression

### 1. Why No Port 53 Firewall Rule Is Created
Standard proctoring configurations make the mistake of creating an outbound allow rule for `UDP/TCP Port 53`. This creates a catastrophic security hole:
- Students can run DNS-tunneling utilities (e.g. `iodine`, `dnscat2`) that encapsulate entire HTTP/VPN sessions inside outbound DNS queries to an authoritative nameserver.
- By deliberately **creating NO port 53 firewall rule**, SPEMCS ensures that student user processes cannot open raw UDP sockets to external DNS resolvers.
- The operating system's built-in `Dnscache` service resolves approved domain names via the local network interface, adhering strictly to campus resolver policies.

### 2. DNS over HTTPS (DoH) Suppression via HKLM Policies
Modern browsers automatically attempt to bypass local DNS servers by resolving domain names over encrypted HTTPS connections (DoH) to Google (`dns.google`) or Cloudflare (`1.1.1.1`).

To close this bypass, SPEMCS writes machine-level policies directly into the Windows Registry:
- **Google Chrome**:
  - Key: `HKLM\SOFTWARE\Policies\Google\Chrome`
  - Value: `DnsOverHttpsMode = "off"`
  - Value: `BuiltInDnsClientEnabled = 0`
- **Microsoft Edge**:
  - Key: `HKLM\SOFTWARE\Policies\Microsoft\Edge`
  - Value: `DnsOverHttpsMode = "off"`
  - Value: `BuiltInDnsClientEnabled = 0`

These policies are enforced as mandatory enterprise directives, disabling the browser's built-in DoH client and forcing all DNS resolution through the controlled Windows stub resolver.

---

## Protocol 41 (6in4 Tunneling) Mitigation

IPv6-in-IPv4 tunneling (Protocol 41) is a common bypass mechanism where modern operating systems encapsulate IPv6 traffic inside ordinary IPv4 packets to tunnel past IPv4-only firewalls.

SPEMCS neutralizes this threat by:
1. Setting the default outbound block on **both IPv4 and IPv6** filtering stacks.
2. Specifically disallowing Protocol 41 traffic in the Windows Filtering Platform policy table.

---

## Which Code Implements It?

- [`WindowsFirewallAdapter.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs):
  - Primary COM wrapper for `HNetCfg.FwPolicy2`.
  - Methods: `SetDefaultOutboundAction()`, `AddRule()`, `RemoveRule()`, `CaptureBaseline()`.
- [`FirewallAddressSpec.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/FirewallAddressSpec.cs):
  - Validates and parses IPv4 / IPv6 addresses, subnets, and comma-separated CIDR strings for COM injection.
- [`BrowserExecutableResolver.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/BrowserExecutableResolver.cs):
  - Scans system directories and registry keys to resolve the exact disk path of `chrome.exe` and `msedge.exe`.
- [`EtwDnsListener.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/EtwDnsListener.cs):
  - Listens to Microsoft-Windows-DNS-Client ETW events to correlate domain resolutions with active processes.

---

## What Happens When It Fails?

| Network Failure State | Internal Cause | Fallback / Recovery Mechanism | Code Location |
| :--- | :--- | :--- | :--- |
| **COM Interop Lockup** | Concurrent rule modification | Retries up to 3 times with 250ms backoff | [`WindowsFirewallAdapter.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/WindowsFirewallAdapter.cs#L140) |
| **Orphaned Rules after Crash** | Machine rebooted without deactivation | Startup reconciliation sweeps `SPEMCS-*` rules from SQLite journal | [`SqliteRollbackJournal.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/SqliteRollbackJournal.cs#L85) |
| **Invalid CIDR Syntax** | Bad vendor IP range entered by admin | `FirewallAddressSpec` parser rejects format before COM call | [`FirewallAddressSpec.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Core/Network/FirewallAddressSpec.cs#L45) |
| **Registry Permission Denied** | Non-elevated execution attempt | Session 0 service runs as `SYSTEM`, ensuring write access to HKLM | [`Program.cs`](file:///c:/Users/shrma/Desktop/spemcsnew/Endpoint-agent/src/Spemcs.Agent.Service/Program.cs) |
