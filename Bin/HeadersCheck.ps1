# Headers Check Module - Zombie ZIP (CVE-2026-0866), extension/magic mismatch, polyglots
# Scans all file headers in suspicious paths for stored+high-entropy ZIP, PE disguised as doc/image, polyglot PE embedded in doc/image

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"
. "$PSScriptRoot\CacheManager.ps1"

$ModuleName = "HeadersCheck"
$LastTick = Get-Date
$TickInterval = Get-TickInterval -BaseInterval 180
$ZipLocalSig = [byte[]]@(0x50, 0x4b, 0x03, 0x04)
$EntropyThreshold = 7.2
$MaxFileSize = 20MB
$HeaderReadBytes = 128KB
$MaxFilesPerRun = 2000

function Invoke-HeadersCheckOptimized {
    $detections = @()
    $scanPaths = @("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")
    $exclusionPaths = @("$env:ProgramData\Antivirus", "$env:ProgramData\GEDR")
    
    try {
        $scanned = 0
        foreach ($scanPath in $scanPaths) {
            if (-not (Test-Path $scanPath) -or $scanned -ge $MaxFilesPerRun) { break }
            try {
                $skip = $false
                foreach ($ex in $exclusionPaths) {
                    if ($scanPath -like "*$ex*") { $skip = $true; break }
                }
                if ($skip) { continue }
                
                $files = Get-ChildItem -Path $scanPath -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -ge 50 -and $_.Length -le $MaxFileSize } |
                    Select-Object -First ($MaxFilesPerRun - $scanned)
                
                foreach ($f in $files) {
                    $scanned++
                    $rule = $null
                    $pathLower = $f.FullName.ToLower()
                    if ($pathLower -like '*\assembly\*' -or $pathLower -like '*\winsxs\*' -or $pathLower -like '*\microsoft.net\*') { continue }
                    
                    $buf = $null
                    try {
                        $toRead = [Math]::Min($HeaderReadBytes, $f.Length)
                        $stream = [System.IO.File]::OpenRead($f.FullName)
                        $buf = New-Object byte[] $toRead
                        $r = $stream.Read($buf, 0, $toRead)
                        $stream.Close()
                        if ($r -lt 50) { continue }
                    } catch { continue }
                    
                    for ($pos = 0; $pos -le $buf.Length - 30; $pos++) {
                        if ($buf[$pos] -ne 0x50 -or $buf[$pos+1] -ne 0x4b -or $buf[$pos+2] -ne 0x03 -or $buf[$pos+3] -ne 0x04) { continue }
                        $compMethod = [BitConverter]::ToUInt16($buf, $pos + 8)
                        $compSize = [BitConverter]::ToInt32($buf, $pos + 18)
                        $fnLen = [BitConverter]::ToUInt16($buf, $pos + 26)
                        $efLen = [BitConverter]::ToUInt16($buf, $pos + 28)
                        $dataStart = $pos + 30 + $fnLen + $efLen
                        if ($compMethod -ne 0 -or $compSize -lt 64 -or $compSize -gt $MaxFileSize) { $pos += 3; continue }
                        if ($dataStart + 256 -gt $buf.Length) { break }
                        $sampleLen = [Math]::Min([Math]::Min($compSize, 4096), $buf.Length - $dataStart)
                        if ($sampleLen -lt 256) { $pos += 3; continue }
                        $freq = @{}
                        for ($i = 0; $i -lt $sampleLen; $i++) {
                            $b = $buf[$dataStart + $i]
                            if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
                        }
                        $ent = 0
                        foreach ($c in $freq.Values) {
                            $p = $c / $sampleLen
                            if ($p -gt 0) { $ent -= $p * [Math]::Log($p, 2) }
                        }
                        if ($ent -ge $EntropyThreshold) {
                            $rule = "ZombieZip"
                            $detections += @{ FilePath = $f.FullName; Rule = $rule; Entropy = [Math]::Round($ent, 2) }
                            $logPath = "$env:ProgramData\Antivirus\Logs\headers_check_$(Get-Date -Format 'yyyy-MM-dd').log"
                            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$rule|$($f.FullName)|Entropy:$([Math]::Round($ent,2))" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
                            break
                        }
                        $pos = $dataStart + $compSize - 1
                    }
                    if ($rule) { continue }
                    $docImageExts = @('.pdf','.jpg','.jpeg','.png','.gif','.bmp','.txt','.doc','.docx','.rtf','.odt','.xls','.xlsx')
                    $ext = [IO.Path]::GetExtension($f.FullName).ToLower()
                    if ($docImageExts -contains $ext -and $buf.Length -ge 2 -and $buf[0] -eq 0x4D -and $buf[1] -eq 0x5A) {
                        $rule = "ExtensionMagicMismatch"
                        $detections += @{ FilePath = $f.FullName; Rule = $rule }
                        $logPath = "$env:ProgramData\Antivirus\Logs\headers_check_$(Get-Date -Format 'yyyy-MM-dd').log"
                        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$rule|$($f.FullName)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
                        continue
                    }
                    $polyglotScan = [Math]::Min(1024, $buf.Length - 2)
                    $startsAsDoc = ($buf.Length -ge 4 -and $buf[0] -eq 0x25 -and $buf[1] -eq 0x50 -and $buf[2] -eq 0x44 -and $buf[3] -eq 0x46) -or
                        ($buf.Length -ge 8 -and $buf[0] -eq 0x89 -and $buf[1] -eq 0x50 -and $buf[2] -eq 0x4E -and $buf[3] -eq 0x47) -or
                        ($buf.Length -ge 4 -and $buf[0] -eq 0x47 -and $buf[1] -eq 0x49 -and $buf[2] -eq 0x46 -and $buf[3] -in 0x38,0x39) -or
                        ($buf.Length -ge 3 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xD8 -and $buf[2] -eq 0xFF) -or
                        ($buf.Length -ge 2 -and $buf[0] -eq 0x42 -and $buf[1] -eq 0x4D)
                    if ($startsAsDoc) {
                        for ($i = 2; $i -le $polyglotScan - 2; $i++) {
                            if ($buf[$i] -eq 0x4D -and $buf[$i+1] -eq 0x5A) {
                                $rule = "PolyglotPeEmbedded"
                                $detections += @{ FilePath = $f.FullName; Rule = $rule }
                                $logPath = "$env:ProgramData\Antivirus\Logs\headers_check_$(Get-Date -Format 'yyyy-MM-dd').log"
                                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$rule|$($f.FullName)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
                                break
                            }
                        }
                    }
                }
            } catch { }
        }
        
        if ($detections.Count -gt 0) {
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) malicious header(s) (ZombieZip/ExtensionMagicMismatch/PolyglotPeEmbedded)"
        }
        Write-Output "STATS:$ModuleName`:Scanned=$scanned"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
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
                $null = Invoke-HeadersCheckOptimized
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
