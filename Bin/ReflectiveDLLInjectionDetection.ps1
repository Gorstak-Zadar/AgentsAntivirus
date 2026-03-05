# Reflective DLL Injection Detection Module
# Detects reflective DLL injection and memory-only DLLs

param([hashtable]$ModuleConfig)

$ModuleName = "ReflectiveDLLInjectionDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-ReflectiveDLLInjectionDetection {
    $detections = @()
    
    try {
        # Check for processes with memory-only DLLs (reflective injection indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules
                
                # Check for DLLs that don't exist on disk (reflective injection)
                $memoryOnlyDlls = $modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*" -and
                    -not (Test-Path $_.FileName)
                }
                
                if ($memoryOnlyDlls.Count -gt 0) {
                    foreach ($dll in $memoryOnlyDlls) {
                        # Exclude known legitimate cases
                        if ($dll.ModuleName -in @("kernel32.dll", "ntdll.dll", "user32.dll")) {
                            continue
                        }
                        
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            DllName = $dll.ModuleName
                            BaseAddress = $dll.BaseAddress.ToString()
                            DllPath = $dll.FileName
                            Type = "Memory-Only DLL (Reflective Injection)"
                            Risk = "Critical"
                        }
                    }
                }
                
                # Check for unusual DLL base addresses (heap-based injection)
                $unusualAddresses = $modules | Where-Object {
                    $addr = [Int64]$_.BaseAddress
                    # DLLs loaded at unusual addresses (not typical image base)
                    ($addr -lt 0x400000 -or $addr -gt 0x7FFFFFFF0000) -and
                    $_.FileName -like "*.dll"
                }
                
                if ($unusualAddresses.Count -gt 3) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UnusualAddressCount = $unusualAddresses.Count
                        Type = "DLLs at Unusual Memory Addresses"
                        Risk = "High"
                    }
                }
                
                # Check for processes with many unsigned DLLs in memory
                $unsignedInMemory = 0
                foreach ($mod in $modules) {
                    if ($mod.FileName -like "*.dll" -and (Test-Path $mod.FileName)) {
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $mod.FileName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $mod.FileName -notlike "$env:SystemRoot\*") {
                                $unsignedInMemory++
                            }
                        } catch { }
                    }
                }
                
                if ($unsignedInMemory -gt 10) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UnsignedDllCount = $unsignedInMemory
                        Type = "Many Unsigned DLLs in Memory"
                        Risk = "Medium"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for processes using reflective loading APIs
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine) {
                    # Check for reflective loading patterns in command line
                    if ($proc.CommandLine -match 'VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary|GetProcAddress' -or
                        $proc.CommandLine -match 'reflective|manual.*map|pe.*injection') {
                        
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            CommandLine = $proc.CommandLine
                            Type = "Process Using Reflective Loading APIs"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for hollowed processes (related to reflective injection)
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    $procPath = $procObj.Path
                    $imgPath = $proc.ExecutablePath
                    
                    # Check for path mismatch (process hollowing often uses reflective injection)
                    if ($procPath -and $imgPath -and $procPath -ne $imgPath) {
                        $detections += @{
                            ProcessId = $proc.ProcessId
                            ProcessName = $proc.Name
                            ProcessPath = $procPath
                            ImagePath = $imgPath
                            Type = "Process Hollowing with Reflective Injection"
                            Risk = "Critical"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check Event Log for DLL load failures (may indicate injection attempts)
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object {
                    (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(1) -and
                    $_.Message -match 'DLL.*not.*found|DLL.*load.*failed|reflective'
                }
            
            if ($events.Count -gt 10) {
                $detections += @{
                    EventCount = $events.Count
                    Type = "Excessive DLL Load Failures (Possible Injection Attempts)"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2036 `
                    -Message "REFLECTIVE DLL INJECTION: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\ReflectiveDLL_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.DllName -or $_.BaseAddress)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) reflective DLL injection indicators"
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
                $count = Invoke-ReflectiveDLLInjectionDetection
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
