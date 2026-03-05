# Token Manipulation Detection Module
# Detects token theft and impersonation

param([hashtable]$ModuleConfig)

$ModuleName = "TokenManipulationDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-TokenManipulationScan {
    $detections = @()
    
    try {
        # Check for processes with unusual token privileges
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, ParentProcessId
        
        foreach ($proc in $processes) {
            try {
                $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                
                # Check for SeDebugPrivilege (enables token access)
                try {
                    $token = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue
                    # Indirect check - processes accessing LSASS often have this
                    if ($proc.Name -eq "lsass.exe") {
                        # Check for processes accessing LSASS
                        $accessingProcs = Get-CimInstance Win32_Process | 
                            Where-Object { $_.ParentProcessId -eq $proc.ProcessId -and 
                                          $_.Name -notin @("svchost.exe", "dwm.exe") }
                        
                        foreach ($accProc in $accessingProcs) {
                            $detections += @{
                                ProcessId = $accProc.ProcessId
                                ProcessName = $accProc.Name
                                Type = "LSASS Access - Possible Token Theft"
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
                
                # Check for processes running as SYSTEM but not in Windows directory
                if ($procObj.StartInfo.UserName -eq "SYSTEM" -or 
                    $proc.Name -eq "SYSTEM") {
                    if ($proc.ExecutablePath -and 
                        $proc.ExecutablePath -notlike "$env:SystemRoot\*") {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ExecutablePath = $proc.ExecutablePath
                            Type = "SYSTEM token on non-Windows executable"
                            Risk = "High"
                        }
                    }
                }
                
            } catch {
                continue
            }
        }
        
        # Check Security Event Log for token operations
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $subjectUserName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
                $targetUserName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                
                # Check for unusual token impersonation
                if ($subjectUserName -ne $targetUserName -and 
                    $targetUserName -eq "SYSTEM") {
                    $detections += @{
                        EventId = $event.Id
                        SubjectUser = $subjectUserName
                        TargetUser = $targetUserName
                        Type = "Token Impersonation - SYSTEM"
                        TimeCreated = $event.TimeCreated
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for common token manipulation tools
        $tokenTools = @("incognito", "mimikatz", "invoke-tokenmanipulation", "getsystem")
        $runningProcs = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $runningProcs) {
            foreach ($tool in $tokenTools) {
                if ($proc.ProcessName -like "*$tool*" -or 
                    $proc.Path -like "*$tool*") {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ProcessPath = $proc.Path
                        Type = "Token Manipulation Tool"
                        Tool = $tool
                        Risk = "Critical"
                    }
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2010 `
                    -Message "TOKEN MANIPULATION: $($detection.ProcessName -or $detection.Type) - $($detection.Tool -or $detection.TargetUser)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\TokenManipulation_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.Risk)|$($_.Tool -or $_.TargetUser)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) token manipulation attempts"
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
                $count = Invoke-TokenManipulationScan
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
