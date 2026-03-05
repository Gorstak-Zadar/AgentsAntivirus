# Network Anomaly Detection Module
# Detects unusual network activity

param([hashtable]$ModuleConfig)

$ModuleName = "NetworkAnomalyDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }
$BaselineConnections = @{}

function Initialize-NetworkBaseline {
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" }
        
        foreach ($conn in $connections) {
            $key = "$($conn.LocalAddress):$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)"
            if (-not $BaselineConnections.ContainsKey($key)) {
                $BaselineConnections[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                }
            }
            $BaselineConnections[$key].Count++
        }
    } catch { }
}

function Invoke-NetworkAnomalyScan {
    $detections = @()
    
    try {
        # Get current network connections
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq "Established" }
        
        # Check for unusual destinations
        $suspiciousIPs = @()
        $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 8080, 8443)
        
        foreach ($conn in $connections) {
            # Check for suspicious ports
            if ($conn.RemotePort -in $suspiciousPorts) {
                $detections += @{
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    State = $conn.State
                    Type = "Suspicious Port"
                    Risk = "High"
                }
            }
            
            # Check for connections to known bad IPs
            if ($conn.RemoteAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
                # Private IP - check if it's unusual
                $key = "$($conn.RemoteAddress):$($conn.RemotePort)"
                if (-not $BaselineConnections.ContainsKey($key)) {
                    $detections += @{
                        LocalAddress = $conn.LocalAddress
                        LocalPort = $conn.LocalPort
                        RemoteAddress = $conn.RemoteAddress
                        RemotePort = $conn.RemotePort
                        Type = "New Connection to Private IP"
                        Risk = "Medium"
                    }
                }
            }
        }
        
        # Check for processes with unusual network activity
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procConnections = $connections | Where-Object {
                        $owner = (Get-NetTCPConnection -OwningProcess $proc.ProcessId -ErrorAction SilentlyContinue)
                        $owner.Count -gt 0
                    }
                    
                    if ($procConnections.Count -gt 50) {
                        # High number of connections
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ConnectionCount = $procConnections.Count
                            Type = "High Network Activity"
                            Risk = "Medium"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for DNS queries to suspicious domains
        try {
            $dnsQueries = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; Id=3008} -ErrorAction SilentlyContinue -MaxEvents 100
            
            $suspiciousDomains = @(".onion", ".bit", ".i2p", "pastebin.com", "githubusercontent.com")
            foreach ($event in $dnsQueries) {
                $message = $event.Message
                foreach ($domain in $suspiciousDomains) {
                    if ($message -like "*$domain*") {
                        $detections += @{
                            EventId = $event.Id
                            Message = $message
                            Type = "Suspicious DNS Query"
                            Domain = $domain
                            Risk = "Medium"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for unusual data transfer
        try {
            $netStats = Get-NetAdapterStatistics -ErrorAction SilentlyContinue
            foreach ($adapter in $netStats) {
                if ($adapter.SentBytes -gt 1GB -or $adapter.ReceivedBytes -gt 1GB) {
                    # High data transfer
                    $timeSpan = (Get-Date) - $LastTick
                    if ($timeSpan.TotalSeconds -gt 0) {
                        $bytesPerSec = $adapter.SentBytes / $timeSpan.TotalSeconds
                        if ($bytesPerSec -gt 10MB) {
                            $detections += @{
                                Adapter = $adapter.Name
                                SentBytes = $adapter.SentBytes
                                ReceivedBytes = $adapter.ReceivedBytes
                                Type = "High Data Transfer Rate"
                                Risk = "Medium"
                            }
                        }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2015 `
                    -Message "NETWORK ANOMALY: $($detection.Type) - $($detection.ProcessName -or $detection.RemoteAddress -or $detection.Adapter)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\NetworkAnomaly_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.RemoteAddress)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) network anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    Initialize-NetworkBaseline
    Start-Sleep -Seconds 10
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-NetworkAnomalyScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{ TickInterval = 30 }
}
