# Optimized Network Traffic Monitoring Module
# Reduced polling and caching of connection state

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"

$ModuleName = "NetworkTrafficMonitoring"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:ConnectionCache = @{}
$script:KnownGoodConnections = @{}

function Invoke-NetworkTrafficMonitoringOptimized {
    $detections = @()
    $maxConnections = Get-ScanLimit -LimitName "MaxConnections"
    $batchSettings = Get-BatchSettings
    
    try {
        $tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Established" } |
            Select-Object -First $maxConnections
        
        $batchCount = 0
        foreach ($conn in $tcpConnections) {
            $key = "$($conn.LocalAddress):$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)"
            
            if ($script:KnownGoodConnections.ContainsKey($key)) {
                continue
            }
            
            $batchCount++
            if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
            }
            
            # Check for suspicious patterns (simplified checks)
            $isPrivate = $conn.RemoteAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)'
            
            if (-not $isPrivate) {
                # Connection to public IP on ephemeral port
                if ($conn.RemotePort -gt 49152) {
                    $detections += @{
                        RemoteAddress = $conn.RemoteAddress
                        RemotePort = $conn.RemotePort
                        Type = "Connection to Public Ephemeral Port"
                        Risk = "Low"
                    }
                }
            } else {
                $script:KnownGoodConnections[$key] = $true
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\NetworkTraffic_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RemoteAddress):$($_.RemotePort)" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) traffic anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Active connections=$($tcpConnections.Count)"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)  # Longer initial delay
    
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
                $count = Invoke-NetworkTrafficMonitoringOptimized
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
