# Process Hollowing Detection Module
# Detects process hollowing attacks

param([hashtable]$ModuleConfig)

$ModuleName = "ProcessHollowingDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }

function Invoke-ProcessHollowingScan {
    $detections = @()
    
    try {
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate
        
        foreach ($proc in $processes) {
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                $procPath = $procObj.Path
                $imgPath = $proc.ExecutablePath
                
                # Check for path mismatch (indicator of process hollowing)
                if ($procPath -and $imgPath -and $procPath -ne $imgPath) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        ProcessPath = $procPath
                        ImagePath = $imgPath
                        Type = "Path Mismatch - Process Hollowing"
                        Risk = "Critical"
                    }
                }
                
                # Check for processes with unusual parent relationships
                if ($proc.ParentProcessId) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction Stop
                        
                        # Check for processes spawned from non-standard parents
                        $suspiciousParents = @{
                            "explorer.exe" = @("notepad.exe", "calc.exe", "cmd.exe", "powershell.exe")
                            "winlogon.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                            "services.exe" = @("cmd.exe", "powershell.exe", "rundll32.exe")
                        }
                        
                        if ($suspiciousParents.ContainsKey($parent.Name)) {
                            if ($proc.Name -in $suspiciousParents[$parent.Name]) {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    ParentProcess = $parent.Name
                                    Type = "Suspicious Parent-Child Relationship"
                                    Risk = "High"
                                }
                            }
                        }
                    } catch { }
                }
                
                # Check for processes with suspended threads (Win32_Thread.ProcessHandle = Win32_Process.Handle, not ProcessId)
                try {
                    $procCim = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ProcessId)" -ErrorAction SilentlyContinue
                    $processHandle = $procCim | Select-Object -ExpandProperty Handle -ErrorAction SilentlyContinue
                    $threads = @()
                    if ($processHandle) {
                        $threads = @(Get-CimInstance Win32_Thread -Filter "ProcessHandle=$processHandle" -ErrorAction SilentlyContinue)
                    }
                    $suspendedThreads = $threads | Where-Object { $_.ThreadState -eq 5 } # Suspended
                    
                    if ($suspendedThreads.Count -gt 0 -and $suspendedThreads.Count -eq $threads.Count) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            SuspendedThreads = $suspendedThreads.Count
                            Type = "All Threads Suspended - Process Hollowing"
                            Risk = "High"
                        }
                    }
                } catch { }
                
                # Check for processes with unusual memory regions
                try {
                    $memoryRegions = Get-Process -Id $proc.ProcessId -ErrorAction Stop | 
                        Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue
                    
                    if ($memoryRegions) {
                        $unknownModules = $memoryRegions | Where-Object { 
                            $_.FileName -notlike "$env:SystemRoot\*" -and
                            $_.FileName -notlike "$env:ProgramFiles*" -and
                            $_.ModuleName -notin @("kernel32.dll", "ntdll.dll", "user32.dll")
                        }
                        
                        if ($unknownModules.Count -gt 5) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                UnknownModules = $unknownModules.Count
                                Type = "Unusual Memory Modules"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch { }
                
            } catch {
                continue
            }
        }
        
        # Check for processes with unusual PE structure
        try {
            $suspiciousProcs = $processes | Where-Object {
                $_.ExecutablePath -and
                (Test-Path $_.ExecutablePath) -and
                $_.ExecutablePath -notlike "$env:SystemRoot\*"
            }
            
            foreach ($proc in $suspiciousProcs) {
                try {
                    $peInfo = Get-Item $proc.ExecutablePath -ErrorAction Stop
                    
                    # Check if executable is signed
                    $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                    if ($sig.Status -ne "Valid") {
                        # Check if it's impersonating a legitimate process
                        $legitNames = @("svchost.exe", "explorer.exe", "notepad.exe", "calc.exe", "dwm.exe")
                        if ($proc.Name -in $legitNames) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ExecutablePath = $proc.ExecutablePath
                                Type = "Unsigned Executable Impersonating Legitimate Process"
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2011 `
                    -Message "PROCESS HOLLOWING: $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.Type)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessHollowing_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.Type)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) process hollowing indicators"
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
                $count = Invoke-ProcessHollowingScan
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
    Start-Module -Config @{ TickInterval = 20 }
}
