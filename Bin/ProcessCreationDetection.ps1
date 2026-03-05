# Process Creation Detection Module
# Detects WMI-based process creation blocking and suspicious process creation patterns

param([hashtable]$ModuleConfig)

$ModuleName = "ProcessCreationDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-ProcessCreationDetection {
    $detections = @()
    
    try {
        # Check for WMI process creation filters (blockers)
        try {
            $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Query -match 'Win32_ProcessStartTrace|__InstanceCreationEvent.*Win32_Process'
                }
            
            foreach ($filter in $filters) {
                # Check if filter is bound to a consumer that blocks processes
                $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                    Where-Object { $_.Filter -like "*$($filter.Name)*" }
                
                if ($bindings) {
                    foreach ($binding in $bindings) {
                        $consumer = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -like "*$($binding.Consumer)*" }
                        
                        if ($consumer) {
                            # Check if consumer command blocks process creation
                            if ($consumer.CommandLineTemplate -match 'taskkill|Stop-Process|Remove-Process' -or
                                $consumer.CommandLineTemplate -match 'block|deny|prevent') {
                                $detections += @{
                                    FilterName = $filter.Name
                                    ConsumerName = $consumer.Name
                                    CommandLine = $consumer.CommandLineTemplate
                                    Type = "WMI Process Creation Blocker Detected"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check Event Log for process creation failures
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7034} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    $_.Message -match 'process.*failed|service.*failed.*start|start.*failed'
                }
            
            $processFailures = $events | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1)
            }
            
            if ($processFailures.Count -gt 10) {
                $detections += @{
                    EventCount = $processFailures.Count
                    Type = "Excessive Process Creation Failures"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for processes with unusual creation patterns
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, CreationDate, ExecutablePath
            
            # Check for processes spawned in rapid succession
            $recentProcs = $processes | Where-Object {
                (Get-Date) - $_.CreationDate -lt [TimeSpan]::FromMinutes(5)
            }
            
            # Group by parent process
            $parentGroups = $recentProcs | Group-Object ParentProcessId
            
            foreach ($group in $parentGroups) {
                if ($group.Count -gt 20) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($group.Name)" -ErrorAction SilentlyContinue
                        if ($parent) {
                            $detections += @{
                                ParentProcessId = $group.Name
                                ParentProcessName = $parent.Name
                                ChildCount = $group.Count
                                Type = "Rapid Process Creation Spawning"
                                Risk = "Medium"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Check for processes with unusual parent relationships
        try {
            $suspiciousParents = @{
                "winlogon.exe" = @("cmd.exe", "powershell.exe", "wmic.exe")
                "services.exe" = @("cmd.exe", "powershell.exe", "rundll32.exe")
                "explorer.exe" = @("notepad.exe", "calc.exe")
            }
            
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId
            
            foreach ($proc in $processes) {
                if ($proc.ParentProcessId) {
                    try {
                        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                        
                        if ($parent) {
                            foreach ($suspParent in $suspiciousParents.Keys) {
                                if ($parent.Name -eq $suspParent -and 
                                    $proc.Name -in $suspiciousParents[$suspParent]) {
                                    
                                    $detections += @{
                                        ProcessId = $proc.ProcessId
                                        ProcessName = $proc.Name
                                        ParentProcessId = $proc.ParentProcessId
                                        ParentProcessName = $parent.Name
                                        Type = "Suspicious Parent-Child Process Relationship"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2035 `
                    -Message "PROCESS CREATION: $($detection.Type) - $($detection.ProcessName -or $detection.FilterName -or $detection.ParentProcessName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessCreation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.FilterName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) process creation anomalies"
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
                $count = Invoke-ProcessCreationDetection
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
    Start-Module -Config @{ TickInterval = 60 }
}
