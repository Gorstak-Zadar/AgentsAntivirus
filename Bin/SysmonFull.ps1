#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    SysmonFull - Sysmon-style monitoring that logs to Windows Event Log without MSFT's intentional skips.
.DESCRIPTION
    Emulates Sysinternals Sysmon: logs process creation, file create/delete, network connections,
    registry changes to Windows Event Log. Unlike Sysmon, does NOT skip:
    - Network connections (Event ID 3 - disabled by default in Sysmon)
    - Microsoft-signed processes (no blanket exclusions)
    - File delete events (Event ID 26)
.NOTES
    Author: Gorstak | Part of AgentsAntivirus
    Event Log: GEDR-SysmonFull
    Event IDs: 1=ProcessCreate, 2=FileCreate, 3=NetworkConnect, 4=ServiceState, 26=FileDelete, 12/13/14=Registry
#>

param(
    [switch]$Uninstall,
    [switch]$Console
)

$EventLogName = "GEDR-SysmonFull"
$EventSource = "SysmonFull"
$script:LastPids = [System.Collections.Generic.HashSet[int]]::new()
$script:LastNetworkKeys = @{}
$script:LastRegSnapshot = @{}
$script:Running = $true

function Write-SysmonEvent {
    param([int]$EventId, [string]$Message)
    try {
        if (-not (Get-WinEvent -ListLog $EventLogName -ErrorAction SilentlyContinue)) {
            New-EventLog -LogName $EventLogName -Source $EventSource -ErrorAction Stop
        }
    }
    catch {
        if ($_.Exception.Message -notmatch "already exists|source") {
            try { [System.Diagnostics.EventLog]::CreateEventSource($EventSource, $EventLogName) } catch { return }
        }
    }
    try {
        Write-EventLog -LogName $EventLogName -Source $EventSource -EventId $EventId -EntryType Information -Message $Message -ErrorAction SilentlyContinue
        if ($script:Console) { Write-Host "[$EventId] $Message" }
    }
    catch { }
}

function Get-ProcessDetails {
    param([int]$Pid)
    try {
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid" -ErrorAction SilentlyContinue
        if (-not $cim) { return $null }
        return [PSCustomObject]@{ Id = $Pid; Name = $cim.Name; Path = $cim.ExecutablePath; CommandLine = $cim.CommandLine }
    }
    catch { return $null }
}

# Setup Event Log
try {
    if (-not (Get-WinEvent -ListLog $EventLogName -ErrorAction SilentlyContinue)) {
        [System.Diagnostics.EventLog]::CreateEventSource($EventSource, $EventLogName)
    }
}
catch {
    if ($_.Exception.Message -notmatch "already exists") {
        Write-Host "Event log setup failed. Run as Administrator. $_" -ForegroundColor Red
        exit 1
    }
}

$script:Console = $Console.IsPresent
Write-SysmonEvent -EventId 4 -Message "SysmonFull started"

if ($Uninstall) {
    Remove-EventLog -LogName $EventLogName -ErrorAction SilentlyContinue
    Write-Host "SysmonFull uninstalled." -ForegroundColor Green
    exit 0
}

# FileSystemWatchers
$watchPaths = @(
    "$env:TEMP", "$env:LOCALAPPDATA\Temp",
    "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
$fsw = [System.Collections.Generic.List[Object]]::new()
foreach ($p in $watchPaths) {
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        $w = New-Object System.IO.FileSystemWatcher
        $w.Path = $p
        $w.IncludeSubdirectories = $true
        $w.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::CreationTime
        $w.EnableRaisingEvents = $true
        $null = Register-ObjectEvent -InputObject $w -EventName Created -Action {
            $path = $Event.SourceEventArgs.FullPath
            Write-EventLog -LogName "GEDR-SysmonFull" -Source "SysmonFull" -EventId 2 -EntryType Information -Message "File Create: $path" -ErrorAction SilentlyContinue
        }
        $null = Register-ObjectEvent -InputObject $w -EventName Deleted -Action {
            $path = $Event.SourceEventArgs.FullPath
            Write-EventLog -LogName "GEDR-SysmonFull" -Source "SysmonFull" -EventId 26 -EntryType Information -Message "File Delete: $path" -ErrorAction SilentlyContinue
        }
        [void]$fsw.Add($w)
    }
}

# Registry snapshot
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
function Get-RegistrySnapshot {
    $snap = @{}
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            try {
                Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue | ForEach-Object {
                    $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        $snap["$rp|$($_.Name)"] = $_.Value
                    }
                }
            }
            catch { }
        }
    }
    return $snap
}
$script:LastRegSnapshot = Get-RegistrySnapshot

Write-Host "SysmonFull running. Log: $EventLogName. Ctrl+C to stop." -ForegroundColor Green
$tick = 0
try {
    while ($true) {
        Start-Sleep -Seconds 5
        $tick++

        # Event 1: Process Create
        $currentPids = (Get-Process -ErrorAction SilentlyContinue).Id
        foreach ($pid in $currentPids) {
            if (-not $script:LastPids.Contains($pid)) {
                $proc = Get-ProcessDetails -Pid $pid
                if ($proc) {
                    $msg = "Process Create: $($proc.Name) (PID $pid) | $($proc.Path) | $($proc.CommandLine)"
                    Write-SysmonEvent -EventId 1 -Message $msg
                }
            }
        }
        $script:LastPids.Clear()
        foreach ($pid in $currentPids) { [void]$script:LastPids.Add($pid) }

        # Event 3: Network Connect
        $current = @{}
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
            $key = "$($_.OwningProcess)-$($_.RemoteAddress):$($_.RemotePort)"
            $current[$key] = $true
            if (-not $script:LastNetworkKeys.ContainsKey($key)) {
                $proc = Get-ProcessDetails -Pid $_.OwningProcess
                $msg = "Network Connect: $($proc.Name) (PID $($_.OwningProcess)) | $($proc.Path) | Remote: $($_.RemoteAddress):$($_.RemotePort)"
                Write-SysmonEvent -EventId 3 -Message $msg
            }
        }
        $script:LastNetworkKeys = $current

        # Event 12/13/14: Registry
        if ($tick % 6 -eq 0) {
            $curr = Get-RegistrySnapshot
            foreach ($k in $curr.Keys) {
                if (-not $script:LastRegSnapshot.ContainsKey($k)) {
                    Write-SysmonEvent -EventId 12 -Message "Registry Value Set: $k = $($curr[$k])"
                }
                elseif ($script:LastRegSnapshot[$k] -ne $curr[$k]) {
                    Write-SysmonEvent -EventId 13 -Message "Registry Modified: $k"
                }
            }
            foreach ($k in $script:LastRegSnapshot.Keys) {
                if (-not $curr.ContainsKey($k)) {
                    Write-SysmonEvent -EventId 14 -Message "Registry Removed: $k"
                }
            }
            $script:LastRegSnapshot = $curr
        }
    }
}
finally {
    $fsw | ForEach-Object { $_.Dispose() }
}
