# COM Object Monitoring Module
# Monitors COM object instantiation and usage

param([hashtable]$ModuleConfig)

$ModuleName = "COMMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-COMMonitoring {
    $detections = @()
    
    try {
        # Check for suspicious COM objects
        $suspiciousCOMObjects = @(
            "Shell.Application",
            "WScript.Shell",
            "Scripting.FileSystemObject",
            "Excel.Application",
            "Word.Application",
            "InternetExplorer.Application"
        )
        
        # Check running processes for COM usage
        $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
        
        foreach ($proc in $processes) {
            try {
                # Check command line for COM object creation
                if ($proc.CommandLine) {
                    foreach ($comObj in $suspiciousCOMObjects) {
                        if ($proc.CommandLine -like "*$comObj*" -or 
                            $proc.CommandLine -like "*New-Object*$comObj*" -or
                            $proc.CommandLine -like "*CreateObject*$comObj*") {
                            
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $proc.CommandLine
                                COMObject = $comObj
                                Type = "Suspicious COM Object Usage"
                                Risk = "Medium"
                            }
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check Event Log for COM object registration
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Application'} -ErrorAction SilentlyContinue -MaxEvents 500 |
                Where-Object { $_.Message -match 'COM|Component Object Model' }
            
            $registrationEvents = $events | Where-Object {
                $_.Message -match 'registration|registration.*failed|COM.*error'
            }
            
            if ($registrationEvents.Count -gt 5) {
                $detections += @{
                    EventCount = $registrationEvents.Count
                    Type = "Unusual COM Registration Activity"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for COM hijacking
        try {
            $comKeys = @(
                "HKCU:\SOFTWARE\Classes\CLSID",
                "HKLM:\SOFTWARE\Classes\CLSID"
            )
            
            foreach ($comKey in $comKeys) {
                if (Test-Path $comKey) {
                    $clsidKeys = Get-ChildItem -Path $comKey -ErrorAction SilentlyContinue | Select-Object -First 100
                    
                    foreach ($clsid in $clsidKeys) {
                        $inprocServer = Join-Path $clsid.PSPath "InprocServer32"
                        
                        if (Test-Path $inprocServer) {
                            $default = (Get-ItemProperty -Path $inprocServer -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
                            
                            if ($default -and $default -notlike "$env:SystemRoot\*") {
                                $detections += @{
                                    CLSID = $clsid.Name
                                    InprocServer = $default
                                    Type = "COM Hijacking - Non-System InprocServer"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check for Excel/Word automation (common in malware)
        try {
            $excelProcs = Get-Process -Name "EXCEL" -ErrorAction SilentlyContinue
            $wordProcs = Get-Process -Name "WINWORD" -ErrorAction SilentlyContinue
            
            foreach ($proc in ($excelProcs + $wordProcs)) {
                try {
                    $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)").CommandLine
                    
                    if ($commandLine -match '\.vbs|\.js|\.ps1|\.bat|powershell|cmd') {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            CommandLine = $commandLine
                            Type = "Office Application with Script Execution"
                            Risk = "High"
                        }
                    }
                } catch { }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2019 `
                    -Message "COM MONITORING: $($detection.Type) - $($detection.ProcessName -or $detection.CLSID -or $detection.COMObject)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\COMMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.COMObject -or $_.CLSID)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) COM object anomalies"
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
                $count = Invoke-COMMonitoring
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
    Start-Module -Config @{ TickInterval = 60 }
}
