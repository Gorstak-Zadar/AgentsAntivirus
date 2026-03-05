# Beacon Detection Module
# Detects C2 beaconing and command & control communication - Optimized for low resource usage

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"

$ModuleName = "BeaconDetection"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:ConnectionBaseline = @{}
$script:ConnectionHistory = @{}  # Tracks connection timestamps for beacon interval analysis

function Initialize-BeaconBaseline {
    try {
        $maxConnections = Get-ScanLimit -LimitName "MaxConnections"
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" } | Select-Object -First $maxConnections
        
        foreach ($conn in $connections) {
            $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $script:ConnectionBaseline.ContainsKey($key)) {
                $script:ConnectionBaseline[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                }
            }
            $script:ConnectionBaseline[$key].Count++
            $script:ConnectionBaseline[$key].LastSeen = Get-Date
        }
    } catch { }
}

function Invoke-BeaconDetection {
    $detections = @()
    
    try {
        # Monitor for periodic connections (beacon indicator)
        $maxConnections = Get-ScanLimit -LimitName "MaxConnections"
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" } | Select-Object -First $maxConnections
        
        # Group connections by process and remote address - track timestamps for beacon interval analysis
        $now = Get-Date
        $connGroups = $connections | Group-Object -Property @{Expression={$_.OwningProcess}}, @{Expression={$_.RemoteAddress}}
        
        foreach ($group in $connGroups) {
            $procId = $group.Name.Split(',')[0].Trim()
            $remoteIP = $group.Name.Split(',')[1].Trim()
            $historyKey = "${procId}:$remoteIP"
            
            try {
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                if (-not $proc) { continue }
                
                # Record connection timestamp (Get-NetTCPConnection output doesn't reliably have CreationTime)
                if (-not $script:ConnectionHistory.ContainsKey($historyKey)) {
                    $script:ConnectionHistory[$historyKey] = [System.Collections.ArrayList]@()
                }
                $script:ConnectionHistory[$historyKey].Add($now) | Out-Null
                # Keep last 20 timestamps to compute intervals
                while ($script:ConnectionHistory[$historyKey].Count -gt 20) {
                    $script:ConnectionHistory[$historyKey].RemoveAt(0)
                }
                
                $connTimes = $script:ConnectionHistory[$historyKey]
                if ($connTimes.Count -gt 3) {
                    # Calculate intervals between connections
                    $intervals = @()
                    for ($i = 1; $i -lt $connTimes.Count; $i++) {
                        $interval = ($connTimes[$i] - $connTimes[$i-1]).TotalSeconds
                        $intervals += $interval
                    }
                    
                    # Check for regular intervals (beacon indicator)
                    if ($intervals.Count -gt 2) {
                        $avgInterval = ($intervals | Measure-Object -Average).Average
                        $variance = ($intervals | ForEach-Object { [Math]::Pow($_ - $avgInterval, 2) } | Measure-Object -Average).Average
                        $stdDev = [Math]::Sqrt($variance)
                        
                        # Low variance = regular intervals = beacon
                        if ($stdDev -lt $avgInterval * 0.2 -and $avgInterval -gt 10 -and $avgInterval -lt 3600) {
                            $detections += @{
                                ProcessId = $procId
                                ProcessName = $proc.ProcessName
                                RemoteAddress = $remoteIP
                                ConnectionCount = $connTimes.Count
                                AverageInterval = [Math]::Round($avgInterval, 2)
                                Type = "Beacon Pattern Detected"
                                Risk = "High"
                            }
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Cleanup stale connection history (connections not seen this run)
        $currentKeys = @($connGroups | ForEach-Object { $p = $_.Name.Split(','); "$($p[0].Trim()):$($p[1].Trim())" })
        $staleKeys = $script:ConnectionHistory.Keys | Where-Object { $_ -notin $currentKeys }
        foreach ($k in $staleKeys) { $script:ConnectionHistory.Remove($k) }
        
        # Check for connections to suspicious TLDs
        foreach ($conn in $connections) {
            if ($conn.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)') {
                try {
                    $dns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
                    
                    $suspiciousTLDs = @(".onion", ".bit", ".i2p", ".tk", ".ml", ".ga", ".cf")
                    foreach ($tld in $suspiciousTLDs) {
                        if ($dns -like "*$tld") {
                            $detections += @{
                                ProcessId = $conn.OwningProcess
                                RemoteAddress = $conn.RemoteAddress
                                RemoteHost = $dns
                                Type = "Connection to Suspicious TLD"
                                Risk = "Medium"
                            }
                            break
                        }
                    }
                } catch { }
            }
        }
        
        # Check for HTTP/HTTPS connections with small data transfer (beacon)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                    $httpConns = $procConns | Where-Object { $_.RemotePort -in @(80, 443, 8080, 8443) }
                    
                    if ($httpConns.Count -gt 0) {
                        # Check network stats
                        $netStats = Get-Counter "\Process($($proc.ProcessName))\IO Data Bytes/sec" -ErrorAction SilentlyContinue
                        if ($netStats -and $netStats.CounterSamples[0].CookedValue -lt 1000 -and $netStats.CounterSamples[0].CookedValue -gt 0) {
                            # Small but consistent data transfer = beacon
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                DataRate = $netStats.CounterSamples[0].CookedValue
                                ConnectionCount = $httpConns.Count
                                Type = "Low Data Transfer Beacon Pattern"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for processes with connections to many different IPs (C2 rotation)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                $uniqueIPs = ($procConns | Select-Object -Unique RemoteAddress).RemoteAddress.Count
                
                if ($uniqueIPs -gt 10) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UniqueIPs = $uniqueIPs
                        ConnectionCount = $procConns.Count
                        Type = "Multiple C2 Connections (IP Rotation)"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2037 `
                    -Message "BEACON DETECTED: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.RemoteAddress -or $detection.RemoteHost)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\BeaconDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.RemoteAddress -or $_.RemoteHost)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) beacon indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    
    Initialize-BeaconBaseline
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
                $count = Invoke-BeaconDetection
                $script:LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
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
