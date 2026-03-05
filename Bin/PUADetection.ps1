# GEDR Detection Job
# Converted from GEDR C# job - FULL IMPLEMENTATION

param([hashtable]$ModuleConfig)

$ModuleName = "PUADetection"
$script:LastRun = [DateTime]::MinValue
$script:TickInterval = 180
$script:SelfPid = $PID

$script:RemoteAccessTools = @(
        "ammyy",
        "ammyadmin",
        "anydesk",
        "atera",
        "connectwise",
        "dameware",
        "logmein",
        "netop",
        "radmin",
        "remcos",
        "rustdesk",
        "screenconnect",
        "showmypc",
        "splashtop",
        "supremo",
        "teamviewer",
        "tightvnc",
        "ultravnc",
        "vnc",
        "vncserver",
        "realvnc"
    )

$script:RogueSecurity = @(
        "antivirus360",
        "antivirus2009",
        "antivirus2010",
        "antispyware",
        "defensewall",
        "drweb-antivirus",
        "errorsafe",
        "fakealert",
        "pcdefender",
        "personalantivirus",
        "privacycenter",
        "registrybooster",
        "registryfix",
        "registrymechanic",
        "securityshield",
        "securitysuite",
        "spyhunter",
        "spywarestop",
        "systemdefender",
        "virusremover",
        "winantivirus",
        "winfixer",
        "winspyware",
        "xpantivirus"
    )

$script:SystemOptimizers = @(
        "advancedsystemcare",
        "auslogics",
        "ccleaner",
        "cleaner",
        "driverbooster",
        "drivereasy",
        "driverfixer",
        "drivermax",
        "driverreviver",
        "driverupdate",
        "glaryutilities",
        "iobit",
        "pcboost",
        "pccleaner",
        "pcfaster",
        "pckeeper",
        "pcmechanic",
        "pcoptimizer",
        "pcspeedup",
        "pctotal",
        "reginout",
        "regclean",
        "registrycleaner",
        "registryreviver",
        "slimcleaner",
        "slimware",
        "speedupmypc",
        "systweak",
        "tuneup",
        "uniblue",
        "wise care",
        "wisecleaner",
        "wiseregistry"
    )

$script:CryptoMiners = @(
        "bfgminer",
        "ccminer",
        "cgminer",
        "claymore",
        "cpuminer",
        "cryptonight",
        "ethminer",
        "gminer",
        "lolminer",
        "minerd",
        "minergate",
        "nanominer",
        "nbminer",
        "nicehash",
        "phoenixminer",
        "sgminer",
        "t-rex",
        "xmr-stak",
        "xmrig",
        "z-enemy"
    )

$script:P2PClients = @(
        "ares",
        "bittorrent",
        "deluge",
        "emule",
        "frostwire",
        "imesh",
        "kazaa",
        "limewire",
        "qbittorrent",
        "transmission",
        "utorrent",
        "vuze"
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
        [string]$LogFile = "puadetection_detections.log"
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
                
        # Check against RogueSecurity patterns
        foreach ($pattern in $script:RogueSecurity) {
            if ($cmdLine -match [regex]::Escape($pattern.ToLower()) -or 
                $procName -match [regex]::Escape($pattern) -or
                $procPath -match [regex]::Escape($pattern)) {
                
                $key = "$($proc.ProcessId)_PUADetection_$pattern"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "PUADetection detected: $($proc.Name) (PID: $($proc.ProcessId)) matched pattern: $pattern"
                    
                    # Invoke threat response if configured
                    if ($ModuleConfig -and $ModuleConfig.AutoKill) {
                        Invoke-ThreatResponse -ProcessId $proc.ProcessId -ProcessName $proc.Name -Reason $pattern
                    }
                }
                break
            }
        }        
        # Check against SystemOptimizers patterns
        foreach ($pattern in $script:SystemOptimizers) {
            if ($cmdLine -match [regex]::Escape($pattern.ToLower()) -or 
                $procName -match [regex]::Escape($pattern) -or
                $procPath -match [regex]::Escape($pattern)) {
                
                $key = "$($proc.ProcessId)_PUADetection_$pattern"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "PUADetection detected: $($proc.Name) (PID: $($proc.ProcessId)) matched pattern: $pattern"
                    
                    # Invoke threat response if configured
                    if ($ModuleConfig -and $ModuleConfig.AutoKill) {
                        Invoke-ThreatResponse -ProcessId $proc.ProcessId -ProcessName $proc.Name -Reason $pattern
                    }
                }
                break
            }
        }        
        # Check against CryptoMiners patterns
        foreach ($pattern in $script:CryptoMiners) {
            if ($cmdLine -match [regex]::Escape($pattern.ToLower()) -or 
                $procName -match [regex]::Escape($pattern) -or
                $procPath -match [regex]::Escape($pattern)) {
                
                $key = "$($proc.ProcessId)_PUADetection_$pattern"
                if (Test-ShouldReport -Key $key) {
                    Write-Detection "PUADetection detected: $($proc.Name) (PID: $($proc.ProcessId)) matched pattern: $pattern"
                    
                    # Invoke threat response if configured
                    if ($ModuleConfig -and $ModuleConfig.AutoKill) {
                        Invoke-ThreatResponse -ProcessId $proc.ProcessId -ProcessName $proc.Name -Reason $pattern
                    }
                }
                break
            }
        }    }
    # Registry-based detection
    $registryPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($regPath in $registryPaths) {
        if (-not (Test-Path $regPath)) { continue }
        
        try {
            $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            $properties = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
            
            foreach ($prop in $properties) {
                $value = $prop.Value
                if ($value -match "\.exe|\.dll|\.ps1|\.vbs|\.bat|powershell|cmd\.exe") {
                    $key = "Reg_$regPath_$($prop.Name)"
                    if (Test-ShouldReport -Key $key) {
                        Write-Detection "Registry persistence found: $regPath\$($prop.Name) = $value" -Level "WARNING"
                    }
                }
            }
        }
        catch {
            # Silent continue on access errors
        }
    }
}
# Main execution
function Invoke-PUADetection {
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
Invoke-PUADetection
