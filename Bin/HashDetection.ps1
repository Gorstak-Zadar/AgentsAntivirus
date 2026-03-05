# Optimized Hash-based Malware Detection Module
# Significantly reduced file I/O and CPU usage

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"
. "$PSScriptRoot\CacheManager.ps1"

$ModuleName = "HashDetection"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName
$script:ThreatHashes = @{}
$script:ScannedFiles = @{}
$script:Initialized = $false

function Initialize-HashDatabaseOptimized {
    if ($script:Initialized) {
        return
    }
    
    $threatPath = "$env:ProgramData\Antivirus\HashDatabase\threats.txt"
    if (Test-Path $threatPath) {
        Get-Content $threatPath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -match '^([A-F0-9]{32,64})$') {
                $script:ThreatHashes[$matches[1].ToUpper()] = $true
            }
        }
    }
    
    $script:Initialized = $true
}

function Invoke-HashScanOptimized {
    $threatsFound = @()
    $batchSettings = Get-BatchSettings
    $maxFiles = Get-ScanLimit -LimitName "MaxFiles"
    
    Initialize-HashDatabaseOptimized
    
    $scanPaths = @("$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads")
    $scannedCount = 0
    
    foreach ($scanPath in $scanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        if ($scannedCount -ge $maxFiles) { break }
        
        try {
            $cutoff = (Get-Date).AddHours(-1)
            $files = Get-ChildItem -Path $scanPath -Include *.exe,*.dll -Recurse -File -ErrorAction SilentlyContinue |
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
                
                $hash = Get-CachedFileHash -FilePath $file.FullName -Algorithm "SHA256"
                if (-not $hash) { continue }
                
                # Mark as scanned
                $script:ScannedFiles[$file.FullName] = @{
                    LastWrite = $file.LastWriteTime
                    Hash = $hash
                }
                
                # Check against threat database
                if ($script:ThreatHashes.ContainsKey($hash.ToUpper())) {
                    $threatsFound += @{
                        File = $file.FullName
                        Hash = $hash
                        Threat = "Known Malware Hash"
                    }
                }
            }
        } catch {
            continue
        }
    }
    
    if ($threatsFound.Count -gt 0) {
        $logPath = "$env:ProgramData\Antivirus\Logs\HashDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
        $threatsFound | ForEach-Object {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|THREAT|$($_.File)|$($_.Hash)" | Add-Content -Path $logPath
        }
        Write-Output "DETECTION:$ModuleName`:Found $($threatsFound.Count) hash-based threats"
    }
    
    Write-Output "STATS:$ModuleName`:Scanned=$scannedCount,Threats=$($threatsFound.Count)"
    
    $now = Get-Date
    $oldKeys = $script:ScannedFiles.Keys | Where-Object {
        -not (Test-Path $_)
    }
    foreach ($key in $oldKeys) {
        $script:ScannedFiles.Remove($key)
    }
    
    Clear-ExpiredCache
    return $threatsFound.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    
    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 60)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-HashScanOptimized
                $script:LastTick = $now
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 60
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{}
}
