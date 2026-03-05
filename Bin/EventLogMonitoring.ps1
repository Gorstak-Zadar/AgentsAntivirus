# Optimized Event Log Monitoring Module
# Reduced Event Log query overhead

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"

$ModuleName = "EventLogMonitoring"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:LastEventTime = @{}

function Invoke-EventLogMonitoringOptimized {
    $detections = @()
    $maxEvents = Get-ScanLimit -LimitName "MaxEvents"
    
    try {
        $lastCheck = if ($script:LastEventTime.ContainsKey('Security')) {
            $script:LastEventTime['Security']
        } else {
            (Get-Date).AddMinutes(-$TickInterval / 60)
        }
        
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                StartTime = $lastCheck
            } -ErrorAction SilentlyContinue -MaxEvents $maxEvents
            
            $script:LastEventTime['Security'] = Get-Date
            
            # Check for failed logons
            $failedLogons = $securityEvents | Where-Object { $_.Id -eq 4625 }
            if ($failedLogons.Count -gt 10) {
                $detections += @{
                    EventCount = $failedLogons.Count
                    Type = "Excessive Failed Logon Attempts"
                    Risk = "High"
                }
            }
            
            # Check for privilege escalation
            $privilegeEvents = $securityEvents | Where-Object { $_.Id -in @(4672, 4673, 4674) }
            if ($privilegeEvents.Count -gt 0) {
                $detections += @{
                    EventCount = $privilegeEvents.Count
                    Type = "Privilege Escalation Events"
                    Risk = "High"
                }
            }
            
            # Check for log clearing
            $logClearing = $securityEvents | Where-Object { $_.Id -eq 1102 }
            if ($logClearing.Count -gt 0) {
                $detections += @{
                    EventCount = $logClearing.Count
                    Type = "Event Log Cleared"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\EventLogMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|Count:$($_.EventCount)" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) event log anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 20)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-EventLogMonitoringOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 60
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{}
}
