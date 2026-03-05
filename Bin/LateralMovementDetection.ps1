# Lateral Movement Detection Module
# Detects lateral movement techniques (SMB, RDP, WMI, PsExec, etc.)

param([hashtable]$ModuleConfig)

$ModuleName = "LateralMovementDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-LateralMovementDetection {
    $detections = @()
    
    try {
        # Check for SMB shares enumeration/access
        try {
            $smbEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                    $_.Message -match 'SMB|share|\\\\.*\\'
                }
            
            if ($smbEvents.Count -gt 10) {
                $detections += @{
                    EventCount = $smbEvents.Count
                    Type = "Excessive SMB Share Access (Lateral Movement)"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for RDP connections
        try {
            $rdpEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object {
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                    $_.Message -match 'RDP|Terminal Services|logon.*type.*10'
                }
            
            if ($rdpEvents.Count -gt 5) {
                foreach ($event in $rdpEvents) {
                    $xml = [xml]$event.ToXml()
                    $subjectUserName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
                    $targetUserName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                    
                    if ($subjectUserName -ne $targetUserName) {
                        $detections += @{
                            EventId = $event.Id
                            SubjectUser = $subjectUserName
                            TargetUser = $targetUserName
                            TimeCreated = $event.TimeCreated
                            Type = "RDP Lateral Movement"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for PsExec usage
        try {
            $processes = Get-CimInstance Win32_Process | 
                Where-Object { 
                    $_.Name -eq "psexec.exe" -or 
                    $_.CommandLine -like "*psexec*" -or
                    $_.CommandLine -like "*paexec*"
                }
            
            foreach ($proc in $processes) {
                $detections += @{
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    CommandLine = $proc.CommandLine
                    Type = "PsExec Lateral Movement Tool"
                    Risk = "High"
                }
            }
        } catch { }
        
        # Check for WMI remote execution
        try {
            $wmiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Trace'} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                    ($_.Message -match 'remote|Win32_Process.*Create' -or $_.Message -match '\\\\')
                }
            
            if ($wmiEvents.Count -gt 5) {
                $detections += @{
                    EventCount = $wmiEvents.Count
                    Type = "WMI Remote Execution (Lateral Movement)"
                    Risk = "High"
                }
            }
        } catch { }
        
        # Check for pass-the-hash tools
        try {
            $pthTools = @("mimikatz", "psexec", "wmiexec", "pth-winexe", "crackmapexec")
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                foreach ($tool in $pthTools) {
                    if ($proc.ProcessName -like "*$tool*" -or $proc.Path -like "*$tool*") {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            Tool = $tool
                            Type = "Pass-the-Hash Tool Detected"
                            Risk = "Critical"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for suspicious network connections to internal IPs
        try {
            $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.State -eq "Established" -and
                    $_.RemoteAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' -and
                    $_.RemotePort -in @(445, 3389, 135, 5985, 5986)  # SMB, RDP, RPC, WinRM
                }
            
            $procGroups = $connections | Group-Object OwningProcess
            
            foreach ($group in $procGroups) {
                $uniqueIPs = ($group.Group | Select-Object -Unique RemoteAddress).RemoteAddress.Count
                
                if ($uniqueIPs -gt 5) {
                    try {
                        $proc = Get-Process -Id $group.Name -ErrorAction SilentlyContinue
                        if ($proc) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                InternalIPCount = $uniqueIPs
                                ConnectionCount = $group.Count
                                Type = "Multiple Internal Network Connections (Lateral Movement)"
                                Risk = "High"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2039 `
                    -Message "LATERAL MOVEMENT: $($detection.Type) - $($detection.ProcessName -or $detection.Tool -or $detection.SubjectUser)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\LateralMovement_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.Tool -or $_.SubjectUser)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) lateral movement indicators"
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
                $count = Invoke-LateralMovementDetection
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
