# PerformanceTweaks.ps1 - Gaming performance optimization module
# Applies low-level Windows tweaks for reduced input latency, smoother frames, and better network responsiveness.
# Safe: all changes are reversible, no security features are disabled.

param([hashtable]$ModuleConfig)

$ModuleName = "PerformanceTweaks"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 86400 }
$script:TweaksApplied = $false

function Write-PerfLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logDir = "$env:ProgramData\Antivirus\Logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    "[$ts] [$Level] [$ModuleName] $Message" | Add-Content -Path "$logDir\PerformanceTweaks_$(Get-Date -Format 'yyyy-MM-dd').log" -ErrorAction SilentlyContinue
}

function Set-RegistryTweak {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        return $true
    } catch {
        Write-PerfLog "Failed to set $Path\$Name : $_" -Level "WARNING"
        return $false
    }
}

function Invoke-PerformanceTweaks {
    if ($script:TweaksApplied) { return 0 }

    $applied = 0
    Write-PerfLog "Applying gaming performance tweaks"

    # --- GPU Hardware Scheduling ---
    if (Set-RegistryTweak "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "HwSchMode" 2) {
        $applied++; Write-PerfLog "GPU hardware scheduling enabled"
    }

    # --- Remove network throttle for non-multimedia traffic ---
    if (Set-RegistryTweak "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 0xFFFFFFFF) {
        $applied++; Write-PerfLog "Network throttling disabled"
    }
    if (Set-RegistryTweak "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0) {
        $applied++; Write-PerfLog "System responsiveness set to 0 (maximum foreground priority)"
    }

    # --- MMCSS Games task priority ---
    $gamesKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Set-RegistryTweak $gamesKey "Background Only" "False" "String"
    Set-RegistryTweak $gamesKey "GPU Priority" 8
    Set-RegistryTweak $gamesKey "Latency Sensitive" "True" "String"
    Set-RegistryTweak $gamesKey "Priority" 6
    Set-RegistryTweak $gamesKey "Scheduling Category" "High" "String"
    Set-RegistryTweak $gamesKey "SFIO Priority" "High" "String"
    Set-RegistryTweak $gamesKey "Clock Rate" 10000
    $applied++; Write-PerfLog "MMCSS Games task configured for foreground priority"

    # --- Disable power throttling ---
    if (Set-RegistryTweak "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" "PowerThrottlingOff" 1) {
        $applied++; Write-PerfLog "Power throttling disabled"
    }

    # --- Nagle's Algorithm disable for lower network latency ---
    if (Set-RegistryTweak "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" "TCPNoDelay" 1) {
        $applied++; Write-PerfLog "Nagle's algorithm disabled (MSMQ)"
    }

    # --- Per-adapter TCP optimizations ---
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $adapters) {
            $ifGuid = $adapter.InterfaceGuid
            $tcpKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$ifGuid"
            Set-RegistryTweak $tcpKey "TcpAckFrequency" 1
            Set-RegistryTweak $tcpKey "TCPNoDelay" 1
            Set-RegistryTweak $tcpKey "TcpDelAckTicks" 0
            Write-PerfLog "TCP optimizations applied to adapter $($adapter.Name)"
        }
        $applied++
    } catch {
        Write-PerfLog "Failed to apply per-adapter TCP tweaks: $_" -Level "WARNING"
    }

    # --- Disable page combining to reduce CPU overhead ---
    if (Set-RegistryTweak "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePageCombining" 1) {
        $applied++; Write-PerfLog "Page combining disabled"
    }

    # --- Consistent timer resolution ---
    if (Set-RegistryTweak "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "GlobalTimerResolutionRequests" 1) {
        $applied++; Write-PerfLog "Global timer resolution requests enabled"
    }

    # --- GameDVR fully disabled ---
    $gdvr = "HKCU:\System\GameConfigStore"
    Set-RegistryTweak $gdvr "GameDVR_Enabled" 0
    Set-RegistryTweak $gdvr "GameDVR_FSEBehaviorMode" 2
    Set-RegistryTweak $gdvr "GameDVR_DSEBehavior" 2
    Set-RegistryTweak $gdvr "GameDVR_EFSEFeatureFlags" 0
    $applied++; Write-PerfLog "GameDVR fully disabled"

    # --- Disable background apps ---
    if (Set-RegistryTweak "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1) {
        $applied++; Write-PerfLog "Background apps disabled"
    }

    # --- Disable Windows tips/suggestions (prevents mid-game popups) ---
    $cdm = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-RegistryTweak $cdm "SubscribedContent-338389Enabled" 0
    Set-RegistryTweak $cdm "SubscribedContent-310093Enabled" 0
    Set-RegistryTweak $cdm "SubscribedContent-338388Enabled" 0
    $applied++; Write-PerfLog "Windows tips/suggestions disabled"

    # --- High Performance power plan (if available) ---
    try {
        $hp = powercfg /list 2>&1 | Select-String "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        if ($hp) {
            powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null
            $applied++; Write-PerfLog "High Performance power plan activated"
        }
    } catch {
        Write-PerfLog "Could not set power plan: $_" -Level "WARNING"
    }

    # --- BCD timer tweaks for consistent frame pacing ---
    try {
        $currentTick = bcdedit /enum "{current}" 2>&1 | Select-String "useplatformtick"
        if (-not $currentTick) {
            bcdedit /set useplatformtick yes 2>$null
            bcdedit /set disabledynamictick yes 2>$null
            $applied++; Write-PerfLog "BCD platform tick and dynamic tick configured"
        }
    } catch {
        Write-PerfLog "Could not set BCD timer tweaks: $_" -Level "WARNING"
    }

    $script:TweaksApplied = $true
    Write-PerfLog "Performance tweaks complete: $applied categories applied"
    return $applied
}

if (-not $ModuleConfig) { Invoke-PerformanceTweaks }
