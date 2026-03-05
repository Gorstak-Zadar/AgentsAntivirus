# Keylogger Detection Module
# Detects keylogging activity

param([hashtable]$ModuleConfig)

$ModuleName = "KeyloggerDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-KeyloggerScan {
    $detections = @()
    
    try {
        # Check for known keylogger processes
        $keyloggerNames = @("keylog", "keylogger", "keyspy", "keycapture", "keystroke", "keyhook", "keymon", "kl")
        
        $processes = Get-Process -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $procNameLower = $proc.ProcessName.ToLower()
            foreach ($keylogName in $keyloggerNames) {
                if ($procNameLower -like "*$keylogName*") {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ProcessPath = $proc.Path
                        Type = "Known Keylogger Process"
                        Risk = "Critical"
                    }
                    break
                }
            }
        }
        
        # Check for processes with keyboard hooks
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Check for SetWindowsHookEx usage (common in keyloggers)
                    $modules = $procObj.Modules | Where-Object { 
                        $_.ModuleName -match "hook|keyboard|input" 
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Check if process is signed
                        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    ExecutablePath = $proc.ExecutablePath
                                    HookModules = $modules.ModuleName -join ','
                                    Type = "Unsigned Process with Keyboard Hooks"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for processes accessing keyboard input devices
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    
                    if ($handles) {
                        # Check for keyboard device access
                        $keyboardHandles = $handles | Where-Object { 
                            $_.Name -match "keyboard|kbdclass|keybd" 
                        }
                        
                        if ($keyboardHandles.Count -gt 0) {
                            # Exclude legitimate processes
                            $legitProcesses = @("explorer.exe", "winlogon.exe", "csrss.exe")
                            if ($proc.ProcessName -notin $legitProcesses) {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    KeyboardHandles = $keyboardHandles.Count
                                    Type = "Direct Keyboard Device Access"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for clipboard monitoring (often used with keyloggers)
        try {
            $clipboardProcs = Get-Process | Where-Object {
                $_.Modules.ModuleName -like "*clipboard*" -or
                $_.Path -like "*clipboard*"
            }
            
            foreach ($proc in $clipboardProcs) {
                if ($proc.ProcessName -notin @("explorer.exe", "dwm.exe")) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        Type = "Clipboard Monitoring Process"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check Event Log for suspicious keyboard events
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'} -ErrorAction SilentlyContinue -MaxEvents 500 |
                Where-Object { $_.Message -match 'keyboard|keystroke|hook' }
            
            if ($events.Count -gt 10) {
                $detections += @{
                    EventCount = $events.Count
                    Type = "Excessive Keyboard Events"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2012 `
                    -Message "KEYLOGGER DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.HookModules -or $detection.Type)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Keylogger_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.Risk)|$($_.HookModules -or $_.KeyboardHandles)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) keylogger indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-KeyloggerScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{ TickInterval = 30 }
}
