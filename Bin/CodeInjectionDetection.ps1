# Code Injection Detection Module
# Detects various code injection techniques

param([hashtable]$ModuleConfig)

$ModuleName = "CodeInjectionDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-CodeInjectionDetection {
    $detections = @()
    
    try {
        # Check for processes with unusual memory regions (injection indicator)
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules
                
                # Check for RWX memory regions (code injection indicator)
                # We'll use heuristics since we can't directly query memory protection
                
                # Check for processes with modules in unusual locations
                $unusualModules = $modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*" -and
                    -not (Test-Path $_.FileName) -and
                    $_.ModuleName -like "*.dll"
                }
                
                if ($unusualModules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        UnusualModules = $unusualModules.Count
                        Type = "Many Unusual Memory Modules (Code Injection)"
                        Risk = "High"
                    }
                }
                
                # Check for processes with unusual thread counts (injection indicator)
                if ($proc.Threads.Count -gt 50 -and $proc.ProcessName -notin @("chrome.exe", "msedge.exe", "firefox.exe")) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        ThreadCount = $proc.Threads.Count
                        Type = "Unusual Thread Count (Possible Injection)"
                        Risk = "Medium"
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for processes using injection APIs
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine) {
                    # Check for code injection API usage
                    $injectionPatterns = @(
                        'VirtualAllocEx',
                        'WriteProcessMemory',
                        'CreateRemoteThread',
                        'NtCreateThreadEx',
                        'RtlCreateUserThread',
                        'SetThreadContext',
                        'QueueUserAPC',
                        'ProcessHollowing',
                        'DLL.*injection',
                        'code.*injection'
                    )
                    
                    foreach ($pattern in $injectionPatterns) {
                        if ($proc.CommandLine -match $pattern) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $proc.CommandLine
                                InjectionPattern = $pattern
                                Type = "Code Injection API Usage"
                                Risk = "High"
                            }
                            break
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes with unusual handle counts (injection indicator)
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.HandleCount -gt 1000 }
            
            foreach ($proc in $processes) {
                # Exclude legitimate processes
                $legitProcesses = @("chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe", "svchost.exe")
                if ($proc.ProcessName -notin $legitProcesses) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        HandleCount = $proc.HandleCount
                        Type = "Unusual Handle Count (Possible Injection)"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check for processes accessing other processes (injection indicator)
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    # Check if process has SeDebugPrivilege (enables injection)
                    # Indirect check through process properties
                    if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                        $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                        
                        # Unsigned processes accessing system processes
                        if ($sig.Status -ne "Valid" -and $proc.Name -match 'debug|inject|hollow') {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                ExecutablePath = $proc.ExecutablePath
                                Type = "Suspicious Process Name (Injection Tool)"
                                Risk = "High"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2038 `
                    -Message "CODE INJECTION: $($detection.Type) - $($detection.ProcessName) (PID: $($detection.ProcessId))"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\CodeInjection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|PID:$($_.ProcessId)|$($_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) code injection indicators"
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
                $count = Invoke-CodeInjectionDetection
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
