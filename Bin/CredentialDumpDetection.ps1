# Credential Dumping Detection Module
# Detects attempts to dump credentials from memory

param([hashtable]$ModuleConfig)

$ModuleName = "CredentialDumpDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }

$CredentialDumpTools = @(
    "mimikatz", "sekurlsa", "lsadump", "wce", "fgdump", 
    "pwdump", "hashdump", "gsecdump", "cachedump",
    "procDump", "dumpert", "nanodump", "mslsa"
)

function Invoke-CredentialDumpScan {
    $detections = @()
    
    try {
        # Check running processes
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath
        
        foreach ($proc in $processes) {
            $procNameLower = $proc.Name.ToLower()
            $cmdLineLower = if ($proc.CommandLine) { $proc.CommandLine.ToLower() } else { "" }
            $pathLower = if ($proc.ExecutablePath) { $proc.ExecutablePath.ToLower() } else { "" }
            
            # Check for credential dumping tools
            foreach ($tool in $CredentialDumpTools) {
                if ($procNameLower -like "*$tool*" -or 
                    $cmdLineLower -like "*$tool*" -or 
                    $pathLower -like "*$tool*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $proc.CommandLine
                        Tool = $tool
                        Risk = "Critical"
                    }
                    break
                }
            }
            
            # Check for suspicious LSASS access
            if ($proc.Name -match "lsass|sam|security") {
                try {
                    $lsassProc = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
                    if ($lsassProc) {
                        # Check if process has handle to LSASS
                        $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.ProcessId)" -ErrorAction SilentlyContinue
                        if ($handles) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                Type = "LSASS Memory Access"
                                Risk = "High"
                            }
                        }
                    }
                } catch { }
            }
        }
        
        # Check for credential dumping API calls in Event Log
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656,4663} -ErrorAction SilentlyContinue -MaxEvents 500
            foreach ($event in $securityEvents) {
                if ($event.Message -match 'lsass|sam|security' -and 
                    $event.Message -match 'Read|Write') {
                    $xml = [xml]$event.ToXml()
                    $objectName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ObjectName'}).'#text'
                    if ($objectName -match 'SAM|SECURITY|SYSTEM') {
                        $detections += @{
                            EventId = $event.Id
                            Type = "Registry Credential Access"
                            ObjectName = $objectName
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2005 `
                    -Message "CREDENTIAL DUMP DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.Tool -or $detection.ObjectName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\CredentialDump_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.Tool -or $_.ObjectName)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) credential dump attempts"
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
                $count = Invoke-CredentialDumpScan
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
    Start-Module -Config @{ TickInterval = 20 }
}
