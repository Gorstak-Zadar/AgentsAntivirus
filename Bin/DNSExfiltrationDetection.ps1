# DNS Exfiltration Detection Module
# Detects data exfiltration via DNS queries

param([hashtable]$ModuleConfig)

$ModuleName = "DNSExfiltrationDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-DNSExfiltrationDetection {
    $detections = @()
    
    try {
        # Monitor DNS queries
        try {
            $dnsEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; Id=3008} -ErrorAction SilentlyContinue -MaxEvents 500
            
            $suspiciousQueries = @()
            
            foreach ($event in $dnsEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $queryName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'QueryName'}).'#text'
                    $queryType = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'QueryType'}).'#text'
                    
                    if ($queryName) {
                        # Check for base64-encoded subdomains (common in DNS exfiltration)
                        $subdomain = $queryName.Split('.')[0]
                        if ($subdomain.Length -gt 20 -and 
                            $subdomain -match '^[A-Za-z0-9+/=]+$' -and
                            $subdomain.Length -gt 50) {
                            $suspiciousQueries += @{
                                QueryName = $queryName
                                QueryType = $queryType
                                TimeCreated = $event.TimeCreated
                                Type = "Base64-Encoded DNS Query"
                                Risk = "High"
                            }
                        }
                        
                        # Check for hex-encoded subdomains
                        if ($subdomain.Length -gt 20 -and 
                            $subdomain -match '^[A-Fa-f0-9]+$' -and
                            $subdomain.Length -gt 50) {
                            $suspiciousQueries += @{
                                QueryName = $queryName
                                QueryType = $queryType
                                TimeCreated = $event.TimeCreated
                                Type = "Hex-Encoded DNS Query"
                                Risk = "High"
                            }
                        }
                        
                        # Check for unusually long domain names
                        if ($queryName.Length -gt 253) {
                            $suspiciousQueries += @{
                                QueryName = $queryName
                                QueryType = $queryType
                                TimeCreated = $event.TimeCreated
                                Type = "Unusually Long DNS Query"
                                Risk = "Medium"
                            }
                        }
                        
                        # Check for queries to suspicious TLDs
                        $suspiciousTLDs = @(".onion", ".bit", ".i2p", ".test", ".local")
                        foreach ($tld in $suspiciousTLDs) {
                            if ($queryName -like "*$tld") {
                                $suspiciousQueries += @{
                                    QueryName = $queryName
                                    QueryType = $queryType
                                    TimeCreated = $event.TimeCreated
                                    Type = "DNS Query to Suspicious TLD"
                                    TLD = $tld
                                    Risk = "Medium"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
            
            $detections += $suspiciousQueries
            
            # Check for excessive DNS queries from single process
            try {
                $processes = Get-Process -ErrorAction SilentlyContinue
                
                foreach ($proc in $processes) {
                    try {
                        $procEvents = $dnsEvents | Where-Object {
                            $_.ProcessId -eq $proc.Id -ErrorAction SilentlyContinue
                        }
                        
                        if ($procEvents.Count -gt 100) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                DNSQueryCount = $procEvents.Count
                                Type = "Excessive DNS Queries from Process"
                                Risk = "High"
                            }
                        }
                    } catch {
                        continue
                    }
                }
            } catch { }
        } catch { }
        
        # Monitor DNS traffic volume
        try {
            $dnsConnections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -eq 53 }
            
            if ($dnsConnections.Count -gt 100) {
                $detections += @{
                    ConnectionCount = $dnsConnections.Count
                    Type = "High DNS Traffic Volume"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for DNS tunneling tools
        try {
            $processes = Get-CimInstance Win32_Process | 
                Where-Object { 
                    $_.Name -match 'dnscat|iodine|dns2tcp|dnsperf'
                }
            
            foreach ($proc in $processes) {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    CommandLine = $proc.CommandLine
                    Type = "DNS Tunneling Tool Detected"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2029 `
                    -Message "DNS EXFILTRATION: $($detection.Type) - $($detection.QueryName -or $detection.ProcessName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\DNSExfiltration_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.QueryName -or $_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) DNS exfiltration indicators"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-DNSExfiltrationDetection
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
