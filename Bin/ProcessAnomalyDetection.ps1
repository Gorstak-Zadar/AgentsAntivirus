# Optimized Process Anomaly Detection Module
# Reduced resource usage with baseline caching

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"
. "$PSScriptRoot\CacheManager.ps1"

$ModuleName = "ProcessAnomalyDetection"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:BaselineProcesses = @{}
$script:KnownGoodProcesses = @{}

function Initialize-BaselineOptimized {
    if ($script:BaselineProcesses.Count -gt 0) {
        return
    }
    
    try {
        $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
        
        $processes = Get-Process -ErrorAction SilentlyContinue | Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $key = $proc.ProcessName
            if (-not $script:BaselineProcesses.ContainsKey($key)) {
                $script:BaselineProcesses[$key] = @{
                    Count = 0
                    FirstSeen = Get-Date
                }
            }
            $script:BaselineProcesses[$key].Count++
        }
    } catch { }
}

function Test-ProcessAnomalyOptimized {
    param($Process)
    
    $anomalies = @()
    
    if ($script:KnownGoodProcesses.ContainsKey($Process.ProcessName)) {
        return $anomalies
    }
    
    if ($Process.Path) {
        $systemPaths = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
        foreach ($sysPath in $systemPaths) {
            if ($Process.Path -like "$sysPath\*") {
                try {
                    $sig = Get-CachedSignature -FilePath $Process.Path
                    if ($sig -and $sig.Status -ne "Valid") {
                        $anomalies += "Unsigned executable in system directory"
                    } elseif ($sig -and $sig.Status -eq "Valid") {
                        $script:KnownGoodProcesses[$Process.ProcessName] = $true
                    }
                } catch { }
            }
        }
    }
    
    return $anomalies
}

function Invoke-ProcessAnomalyScanOptimized {
    $detections = @()
    $batchSettings = Get-BatchSettings
    $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
    
    try {
        Initialize-BaselineOptimized
        
        $processes = Get-Process -ErrorAction SilentlyContinue | 
            Where-Object { $_.Path } |
            Select-Object -First $maxProcs
        
        $batchCount = 0
        foreach ($proc in $processes) {
            if ($script:KnownGoodProcesses.ContainsKey($proc.ProcessName)) {
                continue
            }
            
            $batchCount++
            if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
            }
            
            $anomalies = Test-ProcessAnomalyOptimized -Process $proc
            if ($anomalies.Count -gt 0) {
                $detections += @{
                    ProcessId = $proc.Id
                    ProcessName = $proc.ProcessName
                    Path = $proc.Path
                    Anomalies = $anomalies
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ProcessAnomaly_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.Anomalies -join ';')" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) process anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    Clear-ExpiredCache
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)  # Longer initial delay
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ProcessAnomalyScanOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{}
}
