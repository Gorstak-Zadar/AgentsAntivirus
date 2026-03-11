# Optimized Memory Scanning Module
# Reduced CPU/RAM/Disk usage with caching and batching

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"
. "$PSScriptRoot\CacheManager.ps1"

$ModuleName = "MemoryScanning"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName

$script:ProcessBaseline = @{}
$script:LastBaselineUpdate = Get-Date

function Update-ProcessBaseline {
    $now = Get-Date
    if (($now - $script:LastBaselineUpdate).TotalMinutes -lt 5) {
        return
    }
    
    $script:LastBaselineUpdate = $now
    $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | 
            Where-Object { $_.WorkingSet64 -gt 10MB } |
            Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $key = "$($proc.ProcessName)|$($proc.Id)"
            if (-not $script:ProcessBaseline.ContainsKey($key)) {
                $script:ProcessBaseline[$key] = @{
                    FirstSeen = $now
                    Scanned = $false
                }
            }
        }
        
        $toRemove = @()
        foreach ($key in $script:ProcessBaseline.Keys) {
            $pid = $key.Split('|')[1]
            try {
                $null = Get-Process -Id $pid -ErrorAction Stop
            } catch {
                $toRemove += $key
            }
        }
        foreach ($key in $toRemove) {
            $script:ProcessBaseline.Remove($key)
        }
    } catch { }
}

function Invoke-MemoryScanningOptimized {
    $detections = @()
    $batchSettings = Get-BatchSettings
    $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
    
    try {
        Update-ProcessBaseline
        
        $processes = Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.WorkingSet64 -gt 10MB } |
            Select-Object -First $maxProcs
        
        $batchCount = 0
        foreach ($proc in $processes) {
            try {
                $key = "$($proc.ProcessName)|$($proc.Id)"
                
                if ($script:ProcessBaseline.ContainsKey($key) -and $script:ProcessBaseline[$key].Scanned) {
                    continue
                }
                
                $batchCount++
                if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                    Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
                }
                
                $modules = $proc.Modules | Where-Object {
                    $_.FileName -notlike "$env:SystemRoot\*" -and
                    $_.FileName -notlike "$env:ProgramFiles*"
                }
                
                if ($modules.Count -gt 5) {
                    $detections += @{
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        SuspiciousModules = $modules.Count
                        Type = "Process with Many Non-System Modules"
                        Risk = "Medium"
                    }
                }
                
                if ($script:ProcessBaseline.ContainsKey($key)) {
                    $script:ProcessBaseline[$key].Scanned = $true
                }
                
            } catch {
                continue
            }
        }
        
        $now = Get-Date
        foreach ($key in $script:ProcessBaseline.Keys) {
            if (($now - $script:ProcessBaseline[$key].FirstSeen).TotalSeconds -gt $TickInterval) {
                $script:ProcessBaseline[$key].Scanned = $false
                $script:ProcessBaseline[$key].FirstSeen = $now
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\MemoryScanning_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)|$($_.ProcessId)" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) memory anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Scanned $($processes.Count) processes"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    Clear-ExpiredCache
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    
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
                $count = Invoke-MemoryScanningOptimized
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
