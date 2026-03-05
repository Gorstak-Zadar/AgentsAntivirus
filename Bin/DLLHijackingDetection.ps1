# DLL Hijacking Detection Module
# Detects DLL hijacking attempts

param([hashtable]$ModuleConfig)

$ModuleName = "DLLHijackingDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Test-DLLHijacking {
    param([string]$DllPath)
    
    if (-not (Test-Path $DllPath)) { return $false }
    
    # Check if DLL is in suspicious locations
    $suspiciousPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:APPDATA",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    
    foreach ($susPath in $suspiciousPaths) {
        if ($DllPath -like "$susPath*") {
            return $true
        }
    }
    
    # Check if DLL is unsigned
    try {
        $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
        if ($sig.Status -ne "Valid") {
            return $true
        }
    } catch { }
    
    return $false
}

function Invoke-DLLHijackingScan {
    $detections = @()
    
    try {
        # Check loaded DLLs in processes
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" }
                
                foreach ($module in $modules) {
                    if (Test-DLLHijacking -DllPath $module.FileName) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            DllPath = $module.FileName
                            DllName = $module.ModuleName
                            Risk = "High"
                        }
                    }
                }
            } catch {
                # Access denied or process exited
                continue
            }
        }
        
        # Check for DLLs in application directories
        $appPaths = @(
            "$env:ProgramFiles",
            "$env:ProgramFiles(x86)",
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64"
        )
        
        foreach ($appPath in $appPaths) {
            if (-not (Test-Path $appPath)) { continue }
            
            try {
                $dlls = Get-ChildItem -Path $appPath -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 100
                
                foreach ($dll in $dlls) {
                    if ($dll.DirectoryName -ne "$appPath") {
                        # Check if DLL is signed
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $dll.FullName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    DllPath = $dll.FullName
                                    Type = "Unsigned DLL in application directory"
                                    Risk = "Medium"
                                }
                            }
                        } catch { }
                    }
                }
            } catch { }
        }
        
        # Check Event Log for DLL load failures
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $events) {
                if ($event.Message -match 'DLL.*not.*found|DLL.*load.*failed') {
                    $detections += @{
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Type = "DLL Load Failure"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2009 `
                    -Message "DLL HIJACKING: $($detection.ProcessName -or $detection.Type) - $($detection.DllPath -or $detection.Message)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\DLLHijacking_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.DllPath -or $_.DllName)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) DLL hijacking indicators"
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
                $count = Invoke-DLLHijackingScan
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
