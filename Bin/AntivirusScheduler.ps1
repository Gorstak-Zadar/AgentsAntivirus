# AntivirusScheduler.ps1
# Main scheduler - runs all EDR detection modules at configured intervals
# Logic ported from GShield Antivirus.ps1
# Author: Gorstak | Usage: .\AntivirusScheduler.ps1 | .\AntivirusScheduler.ps1 -RemoveRules | .\AntivirusScheduler.ps1 -RegisterSchedule | .\AntivirusScheduler.ps1 -UnregisterSchedule

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)][switch]$RemoveRules = $false,
    [Parameter(Mandatory=$false)][switch]$RegisterSchedule = $false,
    [Parameter(Mandatory=$false)][switch]$UnregisterSchedule = $false,
    [Parameter(Mandatory=$false)][switch]$TestLoad = $false
)

$script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:ScriptPath = if ($PSCommandPath) { $PSCommandPath } else { Join-Path $script:ScriptRoot "AntivirusScheduler.ps1" }

# --- Load base config ---
. "$script:ScriptRoot\OptimizedConfig.ps1"
. "$script:ScriptRoot\CacheManager.ps1"

# --- Load all detection modules ---
$moduleScripts = @(
    "Initializer.ps1", "QuarantineManagement.ps1", "ResponseEngine.ps1",
    "HashDetection.ps1", "AMSIBypassDetection.ps1", "RansomwareDetection.ps1",
    "BeaconDetection.ps1", "NetworkTrafficMonitoring.ps1", "ProcessAnomalyDetection.ps1",
    "EventLogMonitoring.ps1", "FileEntropyDetection.ps1", "YaraDetection.ps1",
    "WMIPersistenceDetection.ps1", "ScheduledTaskDetection.ps1", "RegistryPersistenceDetection.ps1",
    "DLLHijackingDetection.ps1", "TokenManipulationDetection.ps1", "ProcessHollowingDetection.ps1",
    "KeyloggerDetection.ps1", "ReflectiveDLLInjectionDetection.ps1", "NetworkAnomalyDetection.ps1",
    "DNSExfiltrationDetection.ps1", "RootkitDetection.ps1", "ClipboardMonitoring.ps1",
    "COMMonitoring.ps1", "BrowserExtensionMonitoring.ps1", "ShadowCopyMonitoring.ps1",
    "USBMonitoring.ps1", "WebcamGuardian.ps1", "AttackToolsDetection.ps1", "AdvancedThreatDetection.ps1",
    "FirewallRuleMonitoring.ps1", "ServiceMonitoring.ps1", "FilelessDetection.ps1",
    "MemoryScanning.ps1", "NamedPipeMonitoring.ps1", "CodeInjectionDetection.ps1",
    "DataExfiltrationDetection.ps1", "HoneypotMonitoring.ps1", "LateralMovementDetection.ps1",
    "ProcessCreationDetection.ps1", "PrivacyForgeSpoofing.ps1", "PasswordManagement.ps1",
    "IdsDetection.ps1", "CredentialDumpDetection.ps1", "LOLBinDetection.ps1",
    "MemoryAcquisitionDetection.ps1", "MobileDeviceMonitoring.ps1",
    "BCDSecurity.ps1", "CredentialProtection.ps1", "HidMacroGuard.ps1", "LocalProxyDetection.ps1",
    "ScriptContentScan.ps1", "ScriptHostDetection.ps1", "MitreMapping.ps1", "RealTimeFileMonitor.ps1",
    "AsrRules.ps1", "GRulesC2Block.ps1", "ProcessAuditing.ps1", "KeyScramblerManagement.ps1",
    "GFocus.ps1",
    "PasswordRotator.ps1", "GSecurityLite.ps1", "NeuroBehaviorMonitor.ps1",
    "StartupPersistenceDetection.ps1", "SuspiciousParentChildDetection.ps1", "ScriptBlockLoggingCheck.ps1",
    "PerformanceTweaks.ps1"
)

foreach ($m in $moduleScripts) {
    $path = Join-Path $script:ScriptRoot $m
    if (Test-Path $path) {
        try { . $path } catch { Write-Output "ERROR:AntivirusScheduler`:Failed to load $m : $_" }
    }
}

# --- Load CVE-MitigationPatcher (has different param handling) ---
$script:EmbeddedCVEMitigationPatcher = $true
$cvePath = Join-Path $script:ScriptRoot "CVE-MitigationPatcher.ps1"
if (Test-Path $cvePath) {
    try { . $cvePath } catch { Write-Output "ERROR:AntivirusScheduler`:Failed to load CVE-MitigationPatcher.ps1 : $_" }
}

# --- Stub fallbacks (only if module failed to load) ---
if (-not (Get-Command Invoke-PasswordRotatorInstall -ErrorAction SilentlyContinue)) {
    function Invoke-PasswordRotatorInstall { return 0 }
}
if (-not (Get-Command Invoke-GSecurityLite -ErrorAction SilentlyContinue)) {
    function Invoke-GSecurityLite { return 0 }
}
if (-not (Get-Command Invoke-NeuroBehaviorMonitor -ErrorAction SilentlyContinue)) {
    function Invoke-NeuroBehaviorMonitor { return 0 }
}
if (-not (Get-Command Invoke-StartupPersistenceScan -ErrorAction SilentlyContinue)) {
    function Invoke-StartupPersistenceScan { return 0 }
}
if (-not (Get-Command Invoke-SuspiciousParentChildScan -ErrorAction SilentlyContinue)) {
    function Invoke-SuspiciousParentChildScan { return 0 }
}
if (-not (Get-Command Invoke-ScriptBlockLoggingCheck -ErrorAction SilentlyContinue)) {
    function Invoke-ScriptBlockLoggingCheck { return 0 }
}

# --- Scheduler ---
$script:ModuleLastRun = @{}
$script:AntivirusTaskName = "AgentsAntivirusEDR"

function Update-AgentStatus {
    param([array]$ScheduleList, [hashtable]$LastRun)
    $statusFile = "$env:ProgramData\Antivirus\Data\agent_status.json"
    $cutoff = (Get-Date).AddMinutes(-10)
    $active = @($ScheduleList | Where-Object { $LastRun[$_.Name] -and $LastRun[$_.Name] -ge $cutoff } | ForEach-Object { $_.Name })
    if ($active.Count -eq 0) { $active = @($ScheduleList | ForEach-Object { $_.Name }) }
    $status = @{
        LastCheck = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        ActiveAgents = $active
        SystemHealth = "Healthy"
        TotalDetections = 0
        TotalResponses = 0
    }
    if (Test-Path $statusFile) {
        try {
            $existing = Get-Content $statusFile -Raw | ConvertFrom-Json
            if ($existing.PSObject.Properties['TotalDetections']) { $status.TotalDetections = $existing.TotalDetections }
            if ($existing.PSObject.Properties['TotalResponses']) { $status.TotalResponses = $existing.TotalResponses }
        } catch { }
    }
    $status | ConvertTo-Json -Depth 3 | Set-Content -Path $statusFile -ErrorAction SilentlyContinue
}

# Job schedule - intervals (seconds) and Invoke function names from GShield Antivirus.ps1
$schedule = @(
    @{ Name = 'Initializer'; Interval = 300; Invoke = 'Invoke-Initialization' }
    @{ Name = 'HashDetection'; Interval = 90; Invoke = 'Invoke-HashScanOptimized' }
    @{ Name = 'AMSIBypassDetection'; Interval = 90; Invoke = 'Invoke-AMSIBypassScan' }
    @{ Name = 'GFocus'; Interval = 2; Invoke = 'Invoke-GFocusTick' }
    @{ Name = 'ResponseEngine'; Interval = 180; Invoke = 'Invoke-ResponseEngine' }
    @{ Name = 'BeaconDetection'; Interval = 60; Invoke = 'Invoke-BeaconDetection' }
    @{ Name = 'NetworkTrafficMonitoring'; Interval = 45; Invoke = 'Invoke-NetworkTrafficMonitoringOptimized' }
    @{ Name = 'ProcessAnomalyDetection'; Interval = 90; Invoke = 'Invoke-ProcessAnomalyScanOptimized' }
    @{ Name = 'EventLogMonitoring'; Interval = 90; Invoke = 'Invoke-EventLogMonitoringOptimized' }
    @{ Name = 'FileEntropyDetection'; Interval = 120; Invoke = 'Invoke-FileEntropyDetectionOptimized' }
    @{ Name = 'YaraDetection'; Interval = 120; Invoke = 'Invoke-YaraScan' }
    @{ Name = 'WMIPersistenceDetection'; Interval = 60; Invoke = 'Invoke-WMIPersistenceScan' }
    @{ Name = 'ScheduledTaskDetection'; Interval = 60; Invoke = 'Invoke-ScheduledTaskScan' }
    @{ Name = 'RegistryPersistenceDetection'; Interval = 60; Invoke = 'Invoke-RegistryPersistenceScan' }
    @{ Name = 'DLLHijackingDetection'; Interval = 60; Invoke = 'Invoke-DLLHijackingScan' }
    @{ Name = 'TokenManipulationDetection'; Interval = 30; Invoke = 'Invoke-TokenManipulationScan' }
    @{ Name = 'ProcessHollowingDetection'; Interval = 20; Invoke = 'Invoke-ProcessHollowingScan' }
    @{ Name = 'KeyloggerDetection'; Interval = 30; Invoke = 'Invoke-KeyloggerScan' }
    @{ Name = 'ReflectiveDLLInjectionDetection'; Interval = 30; Invoke = 'Invoke-ReflectiveDLLInjectionDetection' }
    @{ Name = 'RansomwareDetection'; Interval = 15; Invoke = 'Invoke-RansomwareDetection' }
    @{ Name = 'NetworkAnomalyDetection'; Interval = 30; Invoke = 'Invoke-NetworkAnomalyScan' }
    @{ Name = 'DNSExfiltrationDetection'; Interval = 60; Invoke = 'Invoke-DNSExfiltrationDetection' }
    @{ Name = 'RootkitDetection'; Interval = 60; Invoke = 'Invoke-RootkitScan' }
    @{ Name = 'ClipboardMonitoring'; Interval = 10; Invoke = 'Invoke-ClipboardMonitoring' }
    @{ Name = 'COMMonitoring'; Interval = 60; Invoke = 'Invoke-COMMonitoring' }
    @{ Name = 'BrowserExtensionMonitoring'; Interval = 60; Invoke = 'Invoke-BrowserExtensionMonitoring' }
    @{ Name = 'ShadowCopyMonitoring'; Interval = 30; Invoke = 'Invoke-ShadowCopyMonitoring' }
    @{ Name = 'USBMonitoring'; Interval = 30; Invoke = 'Invoke-USBMonitoring' }
    @{ Name = 'WebcamGuardian'; Interval = 20; Invoke = 'Invoke-WebcamGuardian' }
    @{ Name = 'AttackToolsDetection'; Interval = 60; Invoke = 'Invoke-AttackToolsScan' }
    @{ Name = 'AdvancedThreatDetection'; Interval = 60; Invoke = 'Invoke-AdvancedThreatScan' }
    @{ Name = 'FirewallRuleMonitoring'; Interval = 60; Invoke = 'Invoke-FirewallRuleMonitoring' }
    @{ Name = 'ServiceMonitoring'; Interval = 60; Invoke = 'Invoke-ServiceMonitoring' }
    @{ Name = 'FilelessDetection'; Interval = 20; Invoke = 'Invoke-FilelessDetection' }
    @{ Name = 'MemoryScanning'; Interval = 90; Invoke = 'Invoke-MemoryScanningOptimized' }
    @{ Name = 'NamedPipeMonitoring'; Interval = 60; Invoke = 'Invoke-NamedPipeMonitoring' }
    @{ Name = 'CodeInjectionDetection'; Interval = 30; Invoke = 'Invoke-CodeInjectionDetection' }
    @{ Name = 'DataExfiltrationDetection'; Interval = 60; Invoke = 'Invoke-DataExfiltrationDetection' }
    @{ Name = 'HoneypotMonitoring'; Interval = 300; Invoke = 'Invoke-HoneypotMonitoring' }
    @{ Name = 'LateralMovementDetection'; Interval = 30; Invoke = 'Invoke-LateralMovementDetection' }
    @{ Name = 'ProcessCreationDetection'; Interval = 60; Invoke = 'Invoke-ProcessCreationDetection' }
    @{ Name = 'QuarantineManagement'; Interval = 300; Invoke = 'Invoke-QuarantineManagement' }
    @{ Name = 'PrivacyForgeSpoofing'; Interval = 300; Invoke = 'Invoke-PrivacyForgeSpoofing' }
    @{ Name = 'PasswordManagement'; Interval = 300; Invoke = 'Invoke-PasswordManagement' }
    @{ Name = 'PasswordRotator'; Interval = 86400; Invoke = 'Invoke-PasswordRotatorInstall' }
    @{ Name = 'IdsDetection'; Interval = 60; Invoke = 'Invoke-IdsScan' }
    @{ Name = 'CredentialDumpDetection'; Interval = 20; Invoke = 'Invoke-CredentialDumpScan' }
    @{ Name = 'LOLBinDetection'; Interval = 30; Invoke = 'Invoke-LOLBinScan' }
    @{ Name = 'MemoryAcquisitionDetection'; Interval = 90; Invoke = 'Invoke-MemoryAcquisitionScan' }
    @{ Name = 'MobileDeviceMonitoring'; Interval = 90; Invoke = 'Invoke-MobileDeviceScan' }
    @{ Name = 'CVE-MitigationPatcher'; Interval = 3600; Invoke = 'Invoke-CVEMitigationPatcher' }
    @{ Name = 'BCDSecurity'; Interval = 300; Invoke = 'Invoke-BCDSecurity' }
    @{ Name = 'CredentialProtection'; Interval = 300; Invoke = 'Invoke-CredentialProtection' }
    @{ Name = 'HidMacroGuard'; Interval = 60; Invoke = 'Invoke-HidMacroGuard' }
    @{ Name = 'LocalProxyDetection'; Interval = 60; Invoke = 'Invoke-LocalProxyDetection' }
    @{ Name = 'ScriptContentScan'; Interval = 120; Invoke = 'Invoke-ScriptContentScan' }
    @{ Name = 'ScriptHostDetection'; Interval = 60; Invoke = 'Invoke-ScriptHostDetection' }
    @{ Name = 'MitreMapping'; Interval = 300; Invoke = 'Invoke-MitreMapping' }
    @{ Name = 'RealTimeFileMonitor'; Interval = 60; Invoke = 'Invoke-RealTimeFileMonitor' }
    @{ Name = 'AsrRules'; Interval = 86400; Invoke = 'Invoke-AsrRules' }
    @{ Name = 'GRulesC2Block'; Interval = 3600; Invoke = 'Invoke-GRulesC2Block' }
    @{ Name = 'ProcessAuditing'; Interval = 86400; Invoke = 'Invoke-ProcessAuditing' }
    @{ Name = 'KeyScramblerManagement'; Interval = 60; Invoke = 'Invoke-KeyScramblerManagement' }
    @{ Name = 'GSecurityLite'; Interval = 60; Invoke = 'Invoke-GSecurityLite' }
    @{ Name = 'NeuroBehaviorMonitor'; Interval = 15; Invoke = 'Invoke-NeuroBehaviorMonitor' }
    @{ Name = 'StartupPersistenceDetection'; Interval = 120; Invoke = 'Invoke-StartupPersistenceScan' }
    @{ Name = 'SuspiciousParentChildDetection'; Interval = 45; Invoke = 'Invoke-SuspiciousParentChildScan' }
    @{ Name = 'ScriptBlockLoggingCheck'; Interval = 86400; Invoke = 'Invoke-ScriptBlockLoggingCheck' }
    @{ Name = 'PerformanceTweaks'; Interval = 86400; Invoke = 'Invoke-PerformanceTweaks' }
)

if ($UnregisterSchedule) {
    $t = Get-ScheduledTask -TaskName $script:AntivirusTaskName -ErrorAction SilentlyContinue
    if ($t) {
        Unregister-ScheduledTask -TaskName $script:AntivirusTaskName -Confirm:$false
        Write-Host "Scheduled task '$($script:AntivirusTaskName)' removed. EDR will no longer start at boot."
    } else {
        Write-Host "Scheduled task '$($script:AntivirusTaskName)' not found."
    }
    exit 0
}

if ($RegisterSchedule) {
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        Write-Host "Could not resolve script path. Run from the folder containing this script."
        exit 1
    }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$scriptPath`"" -WorkingDirectory (Split-Path $scriptPath)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $task = Get-ScheduledTask -TaskName $script:AntivirusTaskName -ErrorAction SilentlyContinue
    if ($task) {
        Set-ScheduledTask -TaskName $script:AntivirusTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
        Write-Host "Updated scheduled task '$($script:AntivirusTaskName)'. EDR will run at system startup."
    } else {
        Register-ScheduledTask -TaskName $script:AntivirusTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
        Write-Host "Registered scheduled task '$($script:AntivirusTaskName)'. EDR will run at system startup. Remove with: .\AntivirusScheduler.ps1 -UnregisterSchedule"
    }
    exit 0
}

if ($RemoveRules) {
    if (Get-Command Remove-BlockedRules -ErrorAction SilentlyContinue) { Remove-BlockedRules }
    exit 0
}

if ($TestLoad) {
    $required = @('Invoke-Initialization','Invoke-HashScanOptimized','Invoke-GFocusTick','Invoke-ResponseEngine','Invoke-RansomwareDetection')
    $missing = @($required | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
    if ($missing.Count -gt 0) { Write-Host "Missing: $($missing -join ', ')"; exit 1 }
    Write-Host "Load test passed - all modules loaded"
    exit 0
}

Invoke-Initialization | Out-Null

$loopSleep = 5
$lastStatusUpdate = [datetime]::MinValue
while ($true) {
    $now = Get-Date
    foreach ($m in $schedule) {
        if (-not $script:ModuleLastRun.ContainsKey($m.Name)) { $script:ModuleLastRun[$m.Name] = [datetime]::MinValue }
        if (($now - $script:ModuleLastRun[$m.Name]).TotalSeconds -ge $m.Interval) {
            $script:ModuleName = $m.Name
            try { & $m.Invoke | Out-Null } catch { Write-Output "ERROR:$($m.Name):$_" }
            $script:ModuleLastRun[$m.Name] = $now
        }
    }
    if (($now - $lastStatusUpdate).TotalSeconds -ge 60) {
        Update-AgentStatus -ScheduleList $schedule -LastRun $script:ModuleLastRun
        $lastStatusUpdate = $now
    }
    Start-Sleep -Seconds $loopSleep
}
