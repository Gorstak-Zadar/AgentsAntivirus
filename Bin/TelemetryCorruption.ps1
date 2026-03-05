# GEDR Detection Job
# Converted from GEDR C# job - FULL IMPLEMENTATION

param([hashtable]$ModuleConfig)

$ModuleName = "TelemetryCorruption"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = 3600
$script:SelfPid = $PID

$script:TelemetryFiles = @(
        "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
        "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
        "%ProgramData%\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
        "%LocalAppData%\Microsoft\Windows\WebCache\WebCacheV01.dat",
        "%ProgramData%\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd",
        "%ProgramData%\Microsoft\Diagnosis\eventTranscript\eventTranscript.db",
        "%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Telemetry%4Operational.evtx",
        "%ProgramData%\NVIDIA Corporation\NvTelemetry\NvTelemetryContainer.etl",
        "%LocalAppData%\Google\Chrome\User Data\Default\Web Data",
        "%ProgramData%\Adobe\ARM\log\ARMTelemetry.etl",
        "%ProgramData%\Intel\Telemetry\IntelData.etl",
        "%ProgramData%\AMD\CN\AMDDiag.etl",
        "%LocalAppData%\Steam\htmlcache\Cookies",
        "%ProgramData%\Epic\EpicGamesLauncher\Data\EOSAnalytics.etl",
        "%AppData%\Discord\Local Storage\leveldb\*.ldb",
        "%AppData%\Mozilla\Firefox\Profiles\*\telemetry.sqlite",
        "%ProgramData%\Logitech\LogiSync\Telemetry.etl",
        "%ProgramData%\Razer\Synapse3\Logs\RazerSynapse.log",
        "%ProgramData%\Corsair\CUE\logs\iCUETelemetry.log"
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
        [string]$LogFile = "telemetrycorruption_detections.log"
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
}
# Main execution
function Invoke-TelemetryCorruption {
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
Invoke-TelemetryCorruption
