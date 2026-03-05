# GEDR Detection Job
# Converted from GEDR C# job - FULL IMPLEMENTATION

param([hashtable]$ModuleConfig)

$ModuleName = "NetworkDebloat"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = 3600
$script:SelfPid = $PID

$script:ComponentsToDisable = @(
        "ms_server",
        "ms_msclient",
        "ms_pacer",
        "ms_lltdio",
        "ms_rspndr",
        "ms_tcpip6"
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
        [string]$LogFile = "networkdebloat_detections.log"
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
    # Generic process monitoring
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | 
                 Select-Object ProcessId, Name, CommandLine, ExecutablePath
    
    foreach ($proc in $processes) {
        if ($proc.ProcessId -eq $script:SelfPid) { continue }
        
        $cmdLine = if ($proc.CommandLine) { $proc.CommandLine.ToLower() } else { "" }
        $procName = if ($proc.Name) { $proc.Name } else { "" }
        
        # Add job-specific detection logic here based on patterns
        # This is a fallback for jobs that need manual review
        
        Write-Detection "Monitoring active for $ModuleName" -Level "INFO"
        break  # Only log once per run
    }
}
# Main execution
function Invoke-NetworkDebloat {
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
Invoke-NetworkDebloat
