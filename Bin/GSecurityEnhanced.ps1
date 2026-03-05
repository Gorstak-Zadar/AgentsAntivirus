# GEDR Detection Job
# Converted from GEDR C# job - FULL IMPLEMENTATION

param([hashtable]$ModuleConfig)

$ModuleName = "GSecurityEnhanced"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = 30
$script:SelfPid = $PID

$script:BadProcessNames = @(
        "mimikatz",
        "procdump",
        "mimilib",
        "pypykatz",
        "lazagne"
    )

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
        [string]$LogFile = "gsecurityenhanced_detections.log"
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
    # Get all running processes
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine, ExecutablePath
    
    foreach ($proc in $processes) {
        if ($proc.ProcessId -eq $script:SelfPid) { continue }
        
        $cmdLine = if ($proc.CommandLine) { $proc.CommandLine.ToLower() } else { "" }
        $procName = if ($proc.Name) { $proc.Name } else { "" }
        $procPath = if ($proc.ExecutablePath) { $proc.ExecutablePath } else { "" }
                
        # Check against BadProcessNames patterns
        foreach ($pattern in $script:BadProcessNames) {
            if ($cmdLine -match [regex]::Escape($pattern.ToLower()) -or 
                $procName -match [regex]::Escape($pattern) -or
                $procPath -match [regex]::Escape($pattern)) {
                
                $key = "$($proc.ProcessId)_GSecurityEnhanced_$pattern"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "GSecurityEnhanced detected: $($proc.Name) (PID: $($proc.ProcessId)) matched pattern: $pattern"
                    
                    # Invoke threat response if configured
                    if ($ModuleConfig -and $ModuleConfig.AutoKill) {
                        Invoke-ThreatResponse -ProcessId $proc.ProcessId -ProcessName $proc.Name -Reason $pattern
                    }
                }
                break
            }
        }    }
    # File-based detection
    $scanPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    
    $suspiciousExtensions = @(".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd", ".scr")
    
    foreach ($basePath in $scanPaths) {
        if (-not (Test-Path $basePath)) { continue }
        
        try {
            $files = Get-ChildItem -Path $basePath -File -ErrorAction SilentlyContinue | 
                     Where-Object { $suspiciousExtensions -contains $_.Extension.ToLower() }
            
            foreach ($file in $files) {
                $key = "File_$($file.FullName)"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "Suspicious file found: $($file.FullName)" -Level "WARNING"
                }
            }
        }
        catch {
            # Silent continue on access errors
        }
    }
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
}
# Main execution
function Invoke-GSecurityEnhanced {
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
Invoke-GSecurityEnhanced
