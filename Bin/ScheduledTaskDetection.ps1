# Scheduled Task Detection Module
# Detects malicious scheduled tasks

param([hashtable]$ModuleConfig)

$ModuleName = "ScheduledTaskDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-ScheduledTaskScan {
    $detections = @()
    
    try {
        # Get all scheduled tasks
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        
        foreach ($task in $tasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
            $taskActions = $task.Actions
            $taskSettings = $task.Settings
            $suspicious = $false
            $reasons = @()
            
            # Check task actions
            foreach ($action in $taskActions) {
                if ($action.Execute) {
                    $executeLower = $action.Execute.ToLower()
                    
                    # Check for suspicious executables
                    if ($executeLower -match 'powershell|cmd|wscript|cscript|rundll32|mshta') {
                        if ($action.Arguments) {
                            $argsLower = $action.Arguments.ToLower()
                            
                            # Check for suspicious arguments
                            if ($argsLower -match '-encodedcommand|-nop|-w.*hidden|-executionpolicy.*bypass' -or
                                $argsLower -match 'http|https|ftp' -or
                                $argsLower -match 'javascript:|\.hta|\.vbs') {
                                $suspicious = $true
                                $reasons += "Suspicious command line arguments"
                            }
                        }
                        
                        # Check for tasks running as SYSTEM
                        if ($task.Principal.RunLevel -eq "Highest" -or 
                            $task.Principal.UserId -eq "SYSTEM") {
                            $suspicious = $true
                            $reasons += "Runs as SYSTEM/High privilege"
                        }
                    }
                }
            }
            
            # Check for hidden tasks
            if ($taskSettings.Hidden) {
                $suspicious = $true
                $reasons += "Hidden task"
            }
            
            # Check for tasks that run when user is logged off
            if ($taskSettings.RunOnlyIfNetworkAvailable -and 
                $taskSettings.StartWhenAvailable) {
                $suspicious = $true
                $reasons += "Runs when network available (exfiltration risk)"
            }
            
            # Check for tasks in suspicious locations
            foreach ($action in $taskActions) {
                if ($action.WorkingDirectory) {
                    $workDir = $action.WorkingDirectory
                    if ($workDir -match '\$env:|temp|appdata' -and 
                        $workDir -notmatch '^[A-Z]:\\') {
                        $suspicious = $true
                        $reasons += "Suspicious working directory"
                    }
                }
            }
            
            # Check for recently created tasks
            $createdDate = $taskInfo | Select-Object -ExpandProperty 'CreationDate' -ErrorAction SilentlyContinue
            if ($createdDate) {
                $age = (Get-Date) - $createdDate
                if ($age.TotalDays -lt 7) {
                    $suspicious = $true
                    $reasons += "Recently created (within 7 days)"
                }
            }
            
            if ($suspicious) {
                $detections += @{
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    Actions = $taskActions
                    Reasons = $reasons
                    State = $task.State
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2007 `
                    -Message "SUSPICIOUS TASK: $($detection.TaskName) - $($detection.Reasons -join ', ')"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\ScheduledTask_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                $actionStr = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.TaskName)|$($_.Reasons -join ';')|$actionStr" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) suspicious scheduled tasks"
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
                $count = Invoke-ScheduledTaskScan
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
