<p align="center">
  <img src="https://img.shields.io/badge/Windows-64--bit-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell" alt="PowerShell">
  <img src="https://img.shields.io/badge/Version-13.10-00C853?style=for-the-badge" alt="v13.10">
  <img src="https://img.shields.io/badge/Agents-100+-00C853?style=for-the-badge" alt="100+ Agents">
</p>

<h1 align="center">AgentsAntivirus</h1>

<p align="center">
  <strong>Standalone Security Detection Agents</strong><br>
  PowerShell Agents (exported from GEDR) | Zero Dependencies | Run Anywhere
</p>

<p align="center">
  <a href="#-overview">Overview</a> •
  <a href="#-features">Features</a> •
  <a href="#-agents">Agents</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-integration">Integration</a>
</p>

---

## Overview

**AgentsAntivirus** is a collection of **standalone PowerShell security scripts** converted from the [GEDR](../GEDR) C# codebase via `Export-GEDRJobs.ps1`. Each agent is a self-contained detection module that can run independently or be orchestrated together via [GShield](../GShield).

This project serves as the **module library** for the GShield EDR system, providing:
- **Detection agents** — Malware, persistence, injection, network threats, hardening
- **Infrastructure modules** — Config, caching, initialization

---

## Features

| Feature | Description |
|---------|-------------|
| **Standalone** | Each agent runs independently with zero external dependencies |
| **Self-contained** | Includes inline helper functions (logging, deduplication, response) |
| **Portable** | Copy any `.ps1` file anywhere and run it |
| **Lightweight** | 3-10 KB per agent, minimal memory footprint |
| **Real Detection** | Full implementations, not stubs — actual threat detection logic |
| **Composable** | Use individually or combine into single-file EDR via GShield |

---

## Project Structure

```
AgentsAntivirus/
├── README.md
├── Setup.cmd
└── Bin/
    ├── OptimizedConfig.ps1      # Configuration & logging
    ├── CacheManager.ps1         # Signature/hash caching
    ├── Initializer.ps1          # Environment setup
    │
    ├── HashDetection.ps1        # Malware & Files
    ├── RansomwareDetection.ps1
    ├── YaraDetection.ps1
    ├── ...
    │
    ├── ProcessAnomalyDetection.ps1  # Process & Memory
    ├── CodeInjectionDetection.ps1
    ├── MemoryScanning.ps1
    ├── ...
    │
    ├── BeaconDetection.ps1      # Network & C2
    ├── DNSExfiltrationDetection.ps1
    ├── LateralMovementDetection.ps1
    ├── ...
    │
    └── (agents + infrastructure .ps1 files)
```

---

## Agents

### Malware & File Detection (9 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `HashDetection` | 90s | File hash scanning against threat databases |
| `RansomwareDetection` | 15s | Ransom notes, shadow copy deletion, encryption patterns |
| `YaraDetection` | 120s | YARA rule-based signature scanning |
| `FileEntropyDetection` | 120s | High-entropy file detection (packed/encrypted) |
| `HeadersCheck` | 180s | Zombie ZIP, extension/magic mismatch, polyglot PE, steganography (Base64 PE in images, XWorm-style) |
| `AdvancedThreatDetection` | 60s | Scans high-risk paths for suspicious files |
| `RealTimeFileMonitor` | 60s | FileSystemWatcher for real-time file changes |
| `PUPDetection` | 120s | Potentially Unwanted Programs (adware, toolbars) |
| `PUMDetection` | 180s | Potentially Unwanted Modifications (hijacks) |
| `PUADetection` | 180s | Potentially Unwanted Applications (miners, RATs) |

### Process & Memory (10 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `ProcessAnomalyDetection` | 90s | Suspicious parent-child process relationships |
| `ProcessHollowingDetection` | 20s | Hollowed process detection |
| `ProcessCreationDetection` | 60s | WMI process creation monitoring |
| `CodeInjectionDetection` | 30s | VirtualAllocEx, WriteProcessMemory patterns |
| `ReflectiveDLLInjectionDetection` | 30s | In-memory DLL injection |
| `MemoryScanning` | 90s | Process memory signature scanning |
| `MemoryAcquisitionDetection` | 90s | Memory forensics tools detection |
| `FilelessDetection` | 20s | Scripts in memory, WMI, registry execution |
| `TokenManipulationDetection` | 30s | Privilege escalation via tokens |
| `SuspiciousParentChildDetection` | 45s | Known-bad parent-child combos |

### Credentials & Attack Tools (8 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `CredentialDumpDetection` | 20s | LSASS access, SAM/SECURITY hive dumping |
| `CredentialProtection` | 300s | Credential storage monitoring |
| `LOLBinDetection` | 30s | Living-Off-the-Land binary abuse |
| `AttackToolsDetection` | 60s | Mimikatz, Cobalt Strike, Metasploit |
| `IdsDetection` | 60s | Command-line intrusion signatures |
| `AMSIBypassDetection` | 90s | AMSI bypass technique detection |
| `KeyloggerDetection` | 30s | Keyboard hook and keylogger detection |
| `CrudePayloadGuard` | 60s | Crude/obvious payload patterns |

### Persistence (8 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `RegistryPersistenceDetection` | 60s | Run keys, Winlogon, IFEO persistence |
| `ScheduledTaskDetection` | 60s | Malicious scheduled tasks |
| `WMIPersistenceDetection` | 60s | WMI event subscription persistence |
| `WMIPolicyProtection` | 120s | WMI policy tampering |
| `DLLHijackingDetection` | 60s | DLL search order hijacking |
| `ServiceMonitoring` | 60s | Malicious service installations |
| `StartupPersistenceDetection` | 120s | Startup folder persistence |
| `DriverWatcher` | 60s | Non-whitelisted kernel drivers |

### Network & Exfiltration (10 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `BeaconDetection` | 60s | C2 beaconing patterns |
| `NetworkAnomalyDetection` | 30s | Unusual connections and ports |
| `NetworkTrafficMonitoring` | 45s | Active connection monitoring |
| `DNSExfiltrationDetection` | 60s | DNS tunneling detection |
| `DataExfiltrationDetection` | 60s | Data theft patterns |
| `LateralMovementDetection` | 30s | PsExec, WMI, RDP lateral movement |
| `LocalProxyDetection` | 60s | Proxy/tunneling detection |
| `GFocus` | 2s | Browser-focused network monitoring |
| `WMIPhoneHomeDetection` | 60s | WMI process phone-home attempts |
| `FirewallRuleMonitoring` | 60s | Firewall profile status, default actions, overly permissive inbound rules |

### System & Devices (9 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `RootkitDetection` | 60s | Hidden processes, kernel anomalies |
| `ShadowCopyMonitoring` | 30s | VSS deletion (ransomware indicator) |
| `USBMonitoring` | 30s | USB device connections |
| `WebcamGuardian` | 20s | Unauthorized webcam and microphone access |
| `MobileDeviceMonitoring` | 90s | MTP/PTP device monitoring |
| `ClipboardMonitoring` | 10s | Clipboard data theft |
| `BrowserExtensionMonitoring` | 60s | Malicious browser extensions |
| `BCDSecurity` | 300s | Boot configuration protection |
| `HidMacroGuard` | 60s | HID/USB rubber ducky detection |

### Monitoring & Logging (8 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `EventLogMonitoring` | 90s | Security event log analysis |
| `COMMonitoring` | 60s | COM object abuse detection |
| `NamedPipeMonitoring` | 60s | Named pipe monitoring |
| `ScriptHostDetection` | 60s | Suspicious script host activity |
| `ScriptContentScan` | 120s | Malicious script content |
| `ScriptBlockLoggingCheck` | 86400s | PowerShell logging validation |
| `ResponseEngine` | 180s | Centralized response engine |
| `MitreMapping` | 300s | MITRE ATT&CK correlation |

### Performance & System Optimization (1 agent)

| Agent | Interval | Description |
|-------|----------|-------------|
| `PerformanceTweaks` | Daily | GPU scheduling, MMCSS games profile, network throttling, Nagle disable, power throttling, timer resolution, GameDVR disable, High Performance power plan |

### Hardening & Auditing (2 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `ProcessAuditing` | Daily | Enables audit policies: process creation, logon/logoff, special logon, account lockout, command-line logging |
| `AsrRules` | Daily | Attack Surface Reduction rule enforcement |

### Companion Scripts (standalone, run separately)

| Script | Description |
|--------|-------------|
| `SysmonFull.ps1` | Sysmon-style event logging to GEDR-SysmonFull (no MSFT skips). Run as Admin. |
| `AutorunsEnhanced.ps1` | Autoruns + auto-remove unverified + untrusted font check. `-RemoveUnverified` to remove. |

### Privacy & Special (7 agents)

| Agent | Interval | Description |
|-------|----------|-------------|
| `PrivacyForgeSpoofing` | 300s | Device fingerprint spoofing |
| `PasswordManagement` | 300s | Password policy monitoring |
| `KeyScramblerManagement` | 60s | KeyScrambler integration |
| `NeuroBehaviorMonitor` | 15s | Focus abuse, flash stimulus detection |
| `HoneypotMonitoring` | 300s | Honeypot file monitoring |
| `QuarantineManagement` | 300s | Quarantine file management |

---

## Usage

### Run Single Agent

```powershell
# Run any agent directly
.\HashDetection.ps1

# With optional config
.\RansomwareDetection.ps1 -ModuleConfig @{ AutoKill = $true }
```

### Run Multiple Agents

```powershell
# Run specific agents in parallel
$agents = @("HashDetection", "RansomwareDetection", "BeaconDetection")
$agents | ForEach-Object -Parallel {
    & ".\$_.ps1"
}
```

### Continuous Monitoring

```powershell
# Simple loop
while ($true) {
    .\HashDetection.ps1
    Start-Sleep -Seconds 90
}
```

---

## Integration

### With GShield (Recommended)

AgentsAntivirus provides the module library for **GShield**, which combines all agents into a single-file EDR:

```
GEDR (C#)  ──export──>  AgentsAntivirus (PS1)  ──build──>  GShield (Single-file)
```

1. **Export** from GEDR: `.\Export-GEDRJobs.ps1`
2. **Build** GShield: `.\Build-NewSingleFile.ps1`
3. **Run** single-file: `.\Bin\Antivirus.ps1`

### Standalone Deployment

Copy agents to any Windows machine:

```powershell
# Copy to target
Copy-Item .\Bin\*.ps1 -Destination "\\target\C$\Security\Agents\"

# Run on target
Invoke-Command -ComputerName target -ScriptBlock {
    & "C:\Security\Agents\HashDetection.ps1"
}
```

---

## Infrastructure Modules

| Module | Purpose |
|--------|---------|
| `OptimizedConfig.ps1` | CPU-aware adaptive scheduling, tick intervals, logging, deduplication |
| `AntivirusScheduler.ps1` | Main orchestrator — runs all agents on their configured intervals |
| `CacheManager.ps1` | File hash caching, signature caching, process caching |
| `Initializer.ps1` | Directory creation, log setup, config initialization |

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10/11, Server 2016+ |
| **PowerShell** | 5.1+ (built-in) |
| **Privileges** | Administrator (recommended for full detection) |
| **Dependencies** | None — fully self-contained |

---

## Regenerating Agents

To regenerate all agents from the GEDR C# source:

```powershell
cd "D:\Gorstak\My Projects\GEDR"
.\Export-GEDRJobs.ps1
```

This will:
- Parse all GEDR C# job files
- Extract detection patterns and arrays
- Generate PowerShell equivalents with full logic
- Output to `AgentsAntivirus\Bin\`

---

## Related Projects

| Project | Description |
|---------|-------------|
| [GEDR](../GEDR) | C# source — System tray EDR (consumes SysmonFull logs via JobSysmonLogIngestion) |
| [SysmonFull](../SysmonFull) | Sysmon-style event logging without MSFT skips |
| [AutorunsEnhanced](../AutorunsEnhanced) | Autoruns + unverified removal + font check |
| [GShield](../GShield) | Single-file EDR (built from this project) |
| **AgentsAntivirus** | PowerShell agents (this project) |

---

<p align="center">
  <strong>AgentsAntivirus v13.5</strong> | Detection Agents from GEDR | Author: Gorstak
</p>

<p align="center">
  <sub>Part of the GEDR Security Suite</sub>
</p>

---

## Disclaimer

**NO WARRANTY.** THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

**Limitation of Liability.** IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
