# GEDR Detection Job
# Converted from GEDR C# job - FULL IMPLEMENTATION

param([hashtable]$ModuleConfig)

$ModuleName = "PasswordRotator"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = 3600
$script:SelfPid = $PID

# Helper function for deduplication
function Test-ShouldReport {
    param([string]$Key)
    
    if ($null -eq $script:ReportedItems) {
        $script:ReportedItems = @{}
    }
    
    if ($script:ReportedItems.ContainsKey($Key)) {
        return $false
    }
    
    $script:ReportedItems[$Key] = [DateTime]::UtcNow
    return $true
}

# Helper function for logging
function Write-Detection {
    param(
        [string]$Message,
        [string]$Level = "THREAT",
        [string]$LogFile = "passwordrotator_detections.log"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$ModuleName] $Message"
    
    # Write to console
    switch ($Level) {
        "THREAT" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO" { Write-Host $logEntry -ForegroundColor Cyan }
        default { Write-Host $logEntry }
    }
    
    # Write to log file
    $logPath = Join-Path $env:LOCALAPPDATA "GEDR\Logs"
    if (-not (Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }
    Add-Content -Path (Join-Path $logPath $LogFile) -Value $logEntry -ErrorAction SilentlyContinue
}

# Helper function for threat response
function Invoke-ThreatResponse {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason
    )
    
    Write-Detection "Threat response triggered for $ProcessName (PID: $ProcessId) - $Reason"
    
    # Don't kill critical system processes
    $criticalProcesses = @("System", "smss", "csrss", "wininit", "services", "lsass", "svchost", "dwm", "explorer")
    if ($criticalProcesses -contains $ProcessName) {
        Write-Detection "Skipping critical process: $ProcessName" -Level "WARNING"
        return
    }
    
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        Write-Detection "Terminated process: $ProcessName (PID: $ProcessId)"
    }
    catch {
        Write-Detection "Failed to terminate $ProcessName (PID: $ProcessId): $($_.Exception.Message)" -Level "WARNING"
    }
}

function Start-Detection {
    # WMI-based detection
    try {
        # Check for WMI event subscriptions (persistence mechanism)
        $eventFilters = Get-CimInstance -Namespace "root\subscription" -ClassName __EventFilter -ErrorAction SilentlyContinue
        $consumers = Get-CimInstance -Namespace "root\subscription" -ClassName __EventConsumer -ErrorAction SilentlyContinue
        $bindings = Get-CimInstance -Namespace "root\subscription" -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
        
        if ($eventFilters -or $consumers -or $bindings) {
            foreach ($filter in $eventFilters) {
                $key = "WMI_Filter_$($filter.Name)"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "WMI Event Filter found: $($filter.Name) - $($filter.Query)" -Level "WARNING"
                }
            }
            foreach ($consumer in $consumers) {
                $key = "WMI_Consumer_$($consumer.Name)"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "WMI Event Consumer found: $($consumer.Name)" -Level "WARNING"
                }
            }
        }
    }
    catch {
        # Silent continue on WMI errors
    }
    # Scheduled task detection
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | 
                 Where-Object { $_.State -ne "Disabled" }
        
        foreach ($task in $tasks) {
            $actions = $task.Actions
            foreach ($action in $actions) {
                if ($action.Execute) {
                    $execLower = $action.Execute.ToLower()
                    
                    # Check for suspicious task actions
                    if ($execLower -match "powershell|cmd|wscript|cscript|mshta|rundll32") {
                        $key = "Task_$($task.TaskName)"
                        if (Test-ShouldReport -Key $key) {
                            Write-Detection "Suspicious scheduled task: $($task.TaskName) - $($action.Execute) $($action.Arguments)" -Level "WARNING"
                        }
                    }
                }
            }
        }
    }
    catch {
        # Silent continue on task errors
    }
}
# Main execution
function Invoke-PasswordRotator {
    $now = Get-Date
    if ($script:LastRun -ne [DateTime]::MinValue -and ($now - $script:LastRun).TotalSeconds -lt $script:TickInterval) {
        return
    }
    $script:LastRun = $now
    
    try {
        Start-Detection
    }
    catch {
        Write-Detection "Error in $ModuleName : $($_.Exception.Message)" -Level "ERROR"
    }
}

# Execute
Invoke-PasswordRotator
