# Response Engine Module
# Centralized response system for all detection modules - Optimized for low resource usage

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"

$ModuleName = "ResponseEngine"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$ResponseQueue = @()
$ResponseActions = @{
    "Critical" = @("Quarantine", "KillProcess", "BlockNetwork", "Log")
    "High" = @("Quarantine", "Log", "Alert")
    "Medium" = @("Log", "Alert")
    "Low" = @("Log")
}
$ProcessedThreats = @{}

function Invoke-ResponseAction {
    param(
        [hashtable]$Detection,
        [string]$Severity
    )
    
    $actions = $ResponseActions[$Severity]
    if (-not $actions) {
        $actions = @("Log")
    }
    
    $results = @()
    
    foreach ($action in $actions) {
        try {
            switch ($action) {
                "Quarantine" {
                    if ($Detection.FilePath -or $Detection.DllPath) {
                        $filePath = $Detection.FilePath -or $Detection.DllPath
                        if (Test-Path $filePath) {
                            # Import quarantine function if available
                            $quarantineModule = Get-Module -Name "QuarantineManagement" -ErrorAction SilentlyContinue
                            if (-not $quarantineModule) {
                                # Load quarantine module
                                $quarantinePath = Join-Path $PSScriptRoot "QuarantineManagement.ps1"
                                if (Test-Path $quarantinePath) {
                                    . $quarantinePath
                                }
                            }
                            
                            # Call quarantine function
                            if (Get-Command -Name "Invoke-QuarantineFile" -ErrorAction SilentlyContinue) {
                                Invoke-QuarantineFile -FilePath $filePath -Reason "Threat Detected: $($Detection.Type)" -Source $Detection.ModuleName
                                $results += "Quarantined: $filePath"
                            }
                        }
                    }
                }
                
                "KillProcess" {
                    if ($Detection.ProcessId) {
                        try {
                            $proc = Get-Process -Id $Detection.ProcessId -ErrorAction Stop
                            Stop-Process -Id $Detection.ProcessId -Force -ErrorAction Stop
                            $results += "Killed process: $($proc.ProcessName) (PID: $Detection.ProcessId)"
                        } catch {
                            $results += "Failed to kill process PID: $Detection.ProcessId"
                        }
                    }
                }
                
                "BlockNetwork" {
                    if ($Detection.RemoteAddress -or $Detection.RemotePort) {
                        try {
                            # Block network connection using firewall
                            $remoteIP = $Detection.RemoteAddress
                            $remotePort = $Detection.RemotePort
                            
                            if ($remoteIP) {
                                $ruleName = "Block_Threat_$($remoteIP.Replace('.', '_'))"
                                $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                                
                                if (-not $existingRule) {
                                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue | Out-Null
                                    $results += "Blocked network to: $remoteIP"
                                }
                            }
                        } catch {
                            $results += "Failed to block network: $_"
                        }
                    }
                }
                
                "Alert" {
                    # Send alert (can be extended with email, SIEM, etc.)
                    $alertMsg = "ALERT: $($Detection.Type) - $($Detection.ProcessName -or $Detection.FilePath) - Severity: $Severity"
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2100 `
                        -Message $alertMsg
                    $results += "Alert sent: $alertMsg"
                }
                
                "Log" {
                    # Already logged, but add to response log
                    $logPath = "$env:ProgramData\Antivirus\Logs\ResponseEngine_$(Get-Date -Format 'yyyy-MM-dd').log"
                    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$Severity|$($Detection.Type)|$($Detection.ProcessName -or $Detection.FilePath)|$($Detection.ModuleName)"
                    Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
                    $results += "Logged"
                }
            }
        } catch {
            $results += "Error in action $action`: $_"
        }
    }
    
    return $results
}

function Invoke-ResponseEngine {
    $responses = @()
    
    try {
        # Check all module detection logs for new threats
        $logPath = "$env:ProgramData\Antivirus\Logs"
        if (Test-Path $logPath) {
            $today = Get-Date -Format 'yyyy-MM-dd'
            $logFiles = Get-ChildItem -Path $logPath -Filter "*_$today.log" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne "ResponseEngine_$today.log" -and $_.Name -ne "Antivirus_$today.log" }
            
            foreach ($logFile in $logFiles) {
                try {
                    $moduleName = $logFile.BaseName -replace "_$today", ""
                    $logEntries = Get-Content -Path $logFile.FullName -ErrorAction SilentlyContinue | Select-Object -Last 50
                    
                    foreach ($entry in $logEntries) {
                        # Parse log entry (format: timestamp|type|risk|details)
                        if ($entry -match '\|') {
                            $parts = $entry -split '\|'
                            if ($parts.Length -ge 3) {
                                $timestamp = $parts[0]
                                $detectionType = $parts[1]
                                $risk = $parts[2]
                                $details = $parts[3..($parts.Length-1)] -join '|'
                                
                                # Create detection hash
                                $detectionHash = ($moduleName + $timestamp + $detectionType + $details).GetHashCode()
                                
                                # Skip if already processed
                                if ($ProcessedThreats.ContainsKey($detectionHash)) {
                                    continue
                                }
                                
                                # Determine severity from risk level
                                $severity = switch ($risk) {
                                    "Critical" { "Critical" }
                                    "High" { "High" }
                                    "Medium" { "Medium" }
                                    default { "Low" }
                                }
                                
                                # Create detection object
                                $detection = @{
                                    ModuleName = $moduleName
                                    Timestamp = $timestamp
                                    Type = $detectionType
                                    Risk = $risk
                                    Details = $details
                                    Severity = $severity
                                }
                                
                                # Extract ProcessId, FilePath, etc. from details
                                if ($details -match 'PID:(\d+)') {
                                    $detection.ProcessId = [int]$matches[1]
                                }
                                if ($details -match '(.+\.exe|.+\.dll)') {
                                    $detection.FilePath = $matches[1]
                                }
                                if ($details -match '(\d+\.\d+\.\d+\.\d+)') {
                                    $detection.RemoteAddress = $matches[1]
                                }
                                
                                # Execute response actions
                                $actionResults = Invoke-ResponseAction -Detection $detection -Severity $severity
                                
                                # Mark as processed
                                $ProcessedThreats[$detectionHash] = Get-Date
                                
                                $responses += @{
                                    Detection = $detection
                                    Actions = $actionResults
                                    Timestamp = Get-Date
                                }
                                
                                Write-Output "DETECTION:$ModuleName`:Processed $detectionType from $moduleName - Actions: $($actionResults -join ', ')"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        }
        
        # Cleanup old processed threats (older than 24 hours)
        $oldKeys = $ProcessedThreats.Keys | Where-Object {
            ((Get-Date) - $ProcessedThreats[$_]).TotalHours -gt 24
        }
        foreach ($key in $oldKeys) {
            $ProcessedThreats.Remove($key)
        }
        
        # Also check Event Log for detection events (2001-2100)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=2001..2099} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    $_.Source -eq "AntivirusEDR" -and
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5)
                }
            
            foreach ($event in $events) {
                $eventHash = ($event.Id.ToString() + $event.TimeCreated.ToString()).GetHashCode()
                
                if (-not $ProcessedThreats.ContainsKey($eventHash)) {
                    # Parse event message for detection info
                    $message = $event.Message
                    $severity = if ($event.EntryType -eq "Error") { "Critical" } 
                               elseif ($event.EntryType -eq "Warning") { "High" }
                               else { "Medium" }
                    
                    $detection = @{
                        ModuleName = "EventLog"
                        Timestamp = $event.TimeCreated.ToString()
                        Type = $message
                        Severity = $severity
                        EventId = $event.Id
                    }
                    
                    # Extract info from message
                    if ($message -match 'PID:\s*(\d+)') {
                        $detection.ProcessId = [int]$matches[1]
                    }
                    if ($message -match '(?:THREAT|DETECTED|FOUND):\s*(.+?)(?:\s*\||\s*-\s*|$)') {
                        $detection.Details = $matches[1]
                    }
                    
                    # Execute response for critical/high severity
                    if ($severity -in @("Critical", "High")) {
                        $actionResults = Invoke-ResponseAction -Detection $detection -Severity $severity
                        $responses += @{
                            Detection = $detection
                            Actions = $actionResults
                            Timestamp = Get-Date
                        }
                    }
                    
                    $ProcessedThreats[$eventHash] = Get-Date
                }
            }
        } catch { }
        
        if ($responses.Count -gt 0) {
            Write-Output "STATS:$ModuleName`:Processed $($responses.Count) threats"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $responses.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ResponseEngine
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{}
}
