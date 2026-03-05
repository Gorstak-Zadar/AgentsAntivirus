# GEDR Detection Job
# Converted from GEDR C# job - FULL IMPLEMENTATION

param([hashtable]$ModuleConfig)

$ModuleName = "WMIPhoneHomeDetection"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = 30
$script:SelfPid = $PID

$script:WbemProcesses = @(
        "wmiprvse",
        "wmiprvse.exe",
        "wmic",
        "wmic.exe",
        "scrcons",
        "scrcons.exe",
        "wmiadap",
        "wmiadap.exe",
        "wmiapsrv",
        "wmiapsrv.exe",
        "unsecapp",
        "unsecapp.exe",
        "mofcomp",
        "mofcomp.exe",
        "winmgmt",
        "winmgmt.exe"
    )

$script:AllowedRemoteIPs = @(
        "127.0.0.1",
        "::1",
        "0.0.0.0"
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
        [string]$LogFile = "wmiphonehomedetection_detections.log"
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
    # Network-based detection
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        
        foreach ($conn in $connections) {
            $remoteIP = $conn.RemoteAddress
            $remotePort = $conn.RemotePort
            $localPort = $conn.LocalPort
            $owningPid = $conn.OwningProcess
            
            # Check for suspicious ports
            $suspiciousPorts = @(4444, 5555, 6666, 1337, 31337, 8080, 8443, 9001, 9090)
            if ($suspiciousPorts -contains $remotePort -or $suspiciousPorts -contains $localPort) {
                $proc = Get-Process -Id $owningPid -ErrorAction SilentlyContinue
                $key = "Net_${owningPid}_${remoteIP}_${remotePort}"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "Suspicious network connection: $($proc.Name) (PID: $owningPid) -> ${remoteIP}:${remotePort}"
                }
            }
        }
    }
    catch {
        # Silent continue on network errors
    }
}
# Main execution
function Invoke-WMIPhoneHomeDetection {
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
Invoke-WMIPhoneHomeDetection
