# Fileless Malware Detection Module
# Detects fileless malware techniques

param([hashtable]$ModuleConfig)

$ModuleName = "FilelessDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }

function Invoke-FilelessDetection {
    $detections = @()
    
    try {
        # Check for PowerShell in memory execution
        $psProcesses = Get-Process -Name "powershell*","pwsh*" -ErrorAction SilentlyContinue
        
        foreach ($psProc in $psProcesses) {
            try {
                $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($psProc.Id)").CommandLine
                
                if ($commandLine) {
                    # Check for encoded commands
                    if ($commandLine -match '-encodedcommand|-enc|-e\s+[A-Za-z0-9+/=]{100,}') {
                        $detections += @{
                            ProcessId = $psProc.Id
                            ProcessName = $psProc.ProcessName
                            CommandLine = $commandLine
                            Type = "PowerShell Encoded Command Execution"
                            Risk = "High"
                        }
                    }
                    
                    # Check for IEX/Invoke-Expression usage
                    if ($commandLine -match '(?i)(iex|invoke-expression|invoke-expression)') {
                        $detections += @{
                            ProcessId = $psProc.Id
                            ProcessName = $psProc.ProcessName
                            CommandLine = $commandLine
                            Type = "PowerShell IEX Execution"
                            Risk = "High"
                        }
                    }
                    
                    # Check for download and execute
                    if ($commandLine -match '(?i)(downloadstring|downloadfile|webclient|invoke-webrequest).*(http|https|ftp)') {
                        $detections += @{
                            ProcessId = $psProc.Id
                            ProcessName = $psProc.ProcessName
                            CommandLine = $commandLine
                            Type = "PowerShell Download and Execute"
                            Risk = "Critical"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for WMI event consumers (fileless persistence)
        try {
            $wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
            
            foreach ($consumer in $wmiConsumers) {
                if ($consumer.__CLASS -match 'ActiveScript|CommandLine') {
                    $detections += @{
                        ConsumerName = $consumer.Name
                        ConsumerClass = $consumer.__CLASS
                        Type = "WMI Fileless Persistence"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for Registry-based fileless execution
        try {
            $regKeys = @(
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            )
            
            foreach ($regKey in $regKeys) {
                if (Test-Path $regKey) {
                    $values = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
                    if ($values) {
                        $valueProps = $values.PSObject.Properties | Where-Object {
                            $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
                        }
                        
                        foreach ($prop in $valueProps) {
                            $value = $prop.Value
                            
                            # Check for registry-based script execution
                            if ($value -match 'powershell.*-enc|wscript|javascript|vbscript' -and
                                -not (Test-Path $value)) {
                                $detections += @{
                                    RegistryPath = $regKey
                                    ValueName = $prop.Name
                                    Value = $value
                                    Type = "Registry-Based Fileless Execution"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check for .NET reflection-based execution
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'System\.Reflection|System\.CodeDom'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Check for unsigned processes using reflection
                        if ($proc.Path -and (Test-Path $proc.Path)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.Path -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    ReflectionModules = $modules.ModuleName -join ','
                                    Type = "Unsigned Process Using Reflection"
                                    Risk = "Medium"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for memory-only modules
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.FileName -notlike "$env:SystemRoot\*" -and
                        $_.FileName -notlike "$env:ProgramFiles*" -and
                        -not (Test-Path $_.FileName)
                    }
                    
                    if ($modules.Count -gt 5) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            MemoryModules = $modules.Count
                            Type = "Process with Many Memory-Only Modules"
                            Risk = "High"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check Event Log for fileless execution indicators
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object {
                    $_.Message -match 'encodedcommand|iex|invoke-expression|downloadstring'
                }
            
            foreach ($event in $events) {
                $detections += @{
                    EventId = $event.Id
                    TimeCreated = $event.TimeCreated
                    Message = $event.Message
                    Type = "Event Log Fileless Execution Indicator"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2026 `
                    -Message "FILELESS DETECTION: $($detection.Type) - $($detection.ProcessName -or $detection.ConsumerName -or $detection.ValueName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\FilelessDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.ConsumerName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) fileless malware indicators"
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
                $count = Invoke-FilelessDetection
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
