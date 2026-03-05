# Rootkit Detection Module
# Detects rootkit installation and activity

param([hashtable]$ModuleConfig)

$ModuleName = "RootkitDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-RootkitScan {
    $detections = @()
    
    try {
        # Check for hidden processes (rootkit indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        $cimProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | 
            Select-Object ProcessId, Name
        
        $processIds = $processes | ForEach-Object { $_.Id } | Sort-Object -Unique
        $cimProcessIds = $cimProcesses | ForEach-Object { $_.ProcessId } | Sort-Object -Unique
        
        $hiddenProcesses = Compare-Object -ReferenceObject $processIds -DifferenceObject $cimProcessIds
        
        if ($hiddenProcesses) {
            foreach ($hidden in $hiddenProcesses) {
                $detections += @{
                    ProcessId = $hidden.InputObject
                    Type = "Hidden Process Detected"
                    Risk = "Critical"
                }
            }
        }
        
        # Check for hidden files/directories
        try {
            $systemDirs = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
            
            foreach ($dir in $systemDirs) {
                if (Test-Path $dir) {
                    $files = Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Attributes -match 'Hidden' -or $_.Attributes -match 'System' }
                    
                    $suspiciousFiles = $files | Where-Object {
                        $_.Name -match '^(\.|\.\.|sys|drv)' -or
                        $_.Extension -match '^\.(sys|drv|dll)$'
                    }
                    
                    if ($suspiciousFiles.Count -gt 10) {
                        $detections += @{
                            Directory = $dir
                            SuspiciousFiles = $suspiciousFiles.Count
                            Type = "Suspicious Hidden Files in System Directory"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for kernel drivers
        try {
            $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.State -eq "Running" -and
                    $_.PathName -notlike "$env:SystemRoot\*" -or
                    $_.Description -match 'rootkit|stealth|hook'
                }
            
            foreach ($driver in $drivers) {
                $detections += @{
                    DriverName = $driver.Name
                    PathName = $driver.PathName
                    Description = $driver.Description
                    Type = "Suspicious Kernel Driver"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for SSDT hooks (indirectly through Event Log)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008} -ErrorAction SilentlyContinue -MaxEvents 50
            
            $hookIndicators = $events | Where-Object {
                $_.Message -match 'hook|SSDT|kernel|driver.*unexpected'
            }
            
            if ($hookIndicators.Count -gt 0) {
                $detections += @{
                    EventCount = $hookIndicators.Count
                    Type = "SSDT Hook Indicators"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for processes with unusual privileges
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Check for SeDebugPrivilege (common in rootkits)
                    if ($procObj.PrivilegedProcessorTime.TotalSeconds -gt 0 -and 
                        $proc.Name -notin @("csrss.exe", "winlogon.exe", "services.exe")) {
                        # Indirect check - process with unusual privileges
                        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $proc.ExecutablePath -like "$env:SystemRoot\*") {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    ExecutablePath = $proc.ExecutablePath
                                    Type = "Unsigned Process with System Privileges"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for unusual boot entries
        try {
            $bootEntries = Get-CimInstance Win32_BootConfiguration -ErrorAction SilentlyContinue
            
            foreach ($boot in $bootEntries) {
                if ($boot.Description -match 'rootkit|stealth|hook' -or
                    $boot.Description -notlike '*Windows*') {
                    $detections += @{
                        BootEntry = $boot.Description
                        Type = "Suspicious Boot Entry"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2017 `
                    -Message "ROOTKIT DETECTED: $($detection.Type) - $($detection.ProcessName -or $detection.DriverName -or $detection.Directory)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Rootkit_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.DriverName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) rootkit indicators"
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
                $count = Invoke-RootkitScan
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
