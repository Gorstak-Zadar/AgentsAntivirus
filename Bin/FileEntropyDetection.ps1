# Optimized File Entropy Detection Module
# Reduced file I/O with smart sampling

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"
. "$PSScriptRoot\CacheManager.ps1"

$ModuleName = "FileEntropyDetection"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$HighEntropyThreshold = 7.2
$script:ScannedFiles = @{}

function Measure-FileEntropyOptimized {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) { return $null }
        
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        
        $sampleSize = Get-ScanLimit -LimitName "SampleSizeBytes"
        $sampleSize = [Math]::Min($sampleSize, $fileInfo.Length)
        
        if ($sampleSize -eq 0) { return $null }
        
        $stream = [System.IO.File]::OpenRead($FilePath)
        $bytes = New-Object byte[] $sampleSize
        $stream.Read($bytes, 0, $sampleSize) | Out-Null
        $stream.Close()
        
        # Calculate byte frequency
        $freq = @{}
        foreach ($byte in $bytes) {
            if ($freq.ContainsKey($byte)) {
                $freq[$byte]++
            } else {
                $freq[$byte] = 1
            }
        }
        
        # Calculate Shannon entropy
        $entropy = 0
        $total = $bytes.Count
        
        foreach ($count in $freq.Values) {
            $p = $count / $total
            if ($p -gt 0) {
                $entropy -= $p * [Math]::Log($p, 2)
            }
        }
        
        return @{
            Entropy = $entropy
            FileSize = $fileInfo.Length
            SampleSize = $sampleSize
        }
    } catch {
        return $null
    }
}

function Invoke-FileEntropyDetectionOptimized {
    $detections = @()
    $maxFiles = Get-ScanLimit -LimitName "MaxFiles"
    $batchSettings = Get-BatchSettings
    
    try {
        $cutoff = (Get-Date).AddHours(-2)
        $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads")
        
        $scannedCount = 0
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath)) { continue }
            if ($scannedCount -ge $maxFiles) { break }
            
            try {
                $files = Get-ChildItem -Path $scanPath -Include *.exe,*.dll,*.scr -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff } |
                    Select-Object -First ($maxFiles - $scannedCount)
                
                $batchCount = 0
                foreach ($file in $files) {
                    $scannedCount++
                    
                    if ($script:ScannedFiles.ContainsKey($file.FullName)) {
                        $cached = $script:ScannedFiles[$file.FullName]
                        if ($cached.LastWrite -eq $file.LastWriteTime) {
                            continue
                        }
                    }
                    
                    $batchCount++
                    if ($batchCount % $batchSettings.BatchSize -eq 0 -and $batchSettings.BatchDelayMs -gt 0) {
                        Start-Sleep -Milliseconds $batchSettings.BatchDelayMs
                    }
                    
                    $entropyResult = Measure-FileEntropyOptimized -FilePath $file.FullName
                    
                    # Mark as scanned
                    $script:ScannedFiles[$file.FullName] = @{
                        LastWrite = $file.LastWriteTime
                        Entropy = if ($entropyResult) { $entropyResult.Entropy } else { 0 }
                    }
                    
                    if ($entropyResult -and $entropyResult.Entropy -ge $HighEntropyThreshold) {
                        $detections += @{
                            FilePath = $file.FullName
                            FileName = $file.Name
                            Entropy = [Math]::Round($entropyResult.Entropy, 2)
                            Type = "High Entropy File"
                            Risk = "Medium"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\FileEntropy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.FilePath)|Entropy:$($_.Entropy)" |
                    Add-Content -Path $logPath
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) high entropy files"
        }
        
        Write-Output "STATS:$ModuleName`:Scanned=$scannedCount"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    $toRemove = $script:ScannedFiles.Keys | Where-Object { -not (Test-Path $_) }
    foreach ($key in $toRemove) {
        $script:ScannedFiles.Remove($key)
    }
    
    Clear-ExpiredCache
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-FileEntropyDetectionOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{}
}
