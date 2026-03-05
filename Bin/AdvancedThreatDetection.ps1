# Advanced Threat Detection
# High-entropy files in Windows\Temp, System32\Tasks

param([hashtable]$ModuleConfig)

$ModuleName = "AdvancedThreatDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 90 }

. "$PSScriptRoot\CacheManager.ps1" -ErrorAction SilentlyContinue

$ScanPaths = @("$env:SystemRoot\Temp", "$env:SystemRoot\System32\Tasks")
$Extensions = @("*.exe", "*.dll", "*.ps1", "*.vbs")

function Measure-FileEntropy {
    param([string]$FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -eq 0) { return 0 }
        $sample = if ($bytes.Length -gt 4096) { $bytes[0..4095] } else { $bytes }
        $freq = @{}
        foreach ($b in $sample) {
            if (-not $freq.ContainsKey($b)) { $freq[$b] = 0 }
            $freq[$b]++
        }
        $entropy = 0
        foreach ($c in $freq.Values) {
            $p = $c / $sample.Count
            $entropy -= $p * [Math]::Log($p, 2)
        }
        return $entropy
    } catch { return 0 }
}

function Invoke-AdvancedThreatScan {
    $detections = @()
    foreach ($basePath in $ScanPaths) {
        if (-not (Test-Path $basePath)) { continue }
        foreach ($ext in $Extensions) {
            try {
                Get-ChildItem -Path $basePath -Filter $ext -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $ent = Measure-FileEntropy -FilePath $_.FullName
                    if ($ent -gt 7.5) {
                        $detections += @{
                            Path = $_.FullName
                            Entropy = [Math]::Round($ent, 2)
                            Type = "High-Entropy File"
                            Risk = "High"
                        }
                    }
                }
            } catch { }
        }
    }
    
    if ($detections.Count -gt 0) {
        $logPath = "$env:ProgramData\Antivirus\Logs\advanced_threat_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
        $detections | ForEach-Object {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Path)|Entropy:$($_.Entropy)" | Add-Content -Path $logPath
            Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2091 -Message "ADVANCED THREAT: $($_.Path)" -ErrorAction SilentlyContinue
        }
        Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) high-entropy files"
    }
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-AdvancedThreatScan | Out-Null
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 90 } }
