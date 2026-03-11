# Script Content Scan - Suspicious script/RAT patterns in script files
# Scans temp, AppData, downloads for .ps1/.vbs/.bat/.cmd with IEX, DownloadString, encoded, etc.

param([hashtable]$ModuleConfig)

$ModuleName = "ScriptContentScan"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 120 }

$SuspiciousPatterns = @(
    'IEX\s*\(|Invoke-Expression',
    'DownloadString\s*\(|DownloadFile\s*\(',
    '\[Net\.WebClient\]|New-Object\s+Net\.WebClient',
    '-EncodedCommand\s+[A-Za-z0-9+/=]{50,}',
    'FromBase64String|\[Convert\]::FromBase64String',
    'Bypass.*ExecutionPolicy|ExecutionPolicy\s+Bypass',
    'Hidden|WindowStyle\s+Hidden|-w\s+1',
    'WScript\.Shell|Shell\.Application',
    'ADODB\.Stream|Scripting\.FileSystemObject',
    'eval\s*\(|Execute\s*\(|ExecuteGlobal',
    'powershell.*-nop.*-w.*hidden',
    'certutil.*-urlcache.*-split',
    'bitsadmin.*\/transfer',
    'mshta\s+(vbscript|http|https):',
    'regsvr32\s+.*\/s\s+.*scrobj\.dll'
)

$ScanPaths = @(
    $env:TEMP,
    [Environment]::GetFolderPath('LocalApplicationData'),
    (Join-Path $env:USERPROFILE "Downloads"),
    (Join-Path $env:USERPROFILE "Desktop"),
    "C:\Windows\Temp"
)

$MaxFiles = 200
$MaxBytesToRead = 8192

function Test-SuspiciousScriptContent {
    param([string]$Content, [string]$Ext)
    if ([string]::IsNullOrWhiteSpace($Content)) { return $false }
    $contentLower = $Content.ToLower()
    $matchCount = 0
    foreach ($pat in $SuspiciousPatterns) {
        if ($Content -match $pat) { $matchCount++ }
        if ($matchCount -ge 2) { return $true }
    }
    if ($matchCount -ge 1 -and $contentLower -match 'http[s]?://[^\s''"]+') { return $true }
    return $false
}

function Invoke-ScriptContentScan {
    $detections = @()
    try {
        $extensions = @('*.ps1','*.psm1','*.vbs','*.vbe','*.js','*.jse','*.wsf','*.bat','*.cmd','*.hta')
        $totalScanned = 0
        foreach ($root in $ScanPaths) {
            if (-not (Test-Path $root)) { continue }
            foreach ($ext in $extensions) {
                $files = Get-ChildItem -Path $root -Filter $ext -Recurse -File -ErrorAction SilentlyContinue |
                    Select-Object -First ([Math]::Min(50, $MaxFiles - $totalScanned))
                foreach ($f in $files) {
                    $totalScanned++
                    if ($totalScanned -gt $MaxFiles) { break }
                    try {
                        $raw = [System.IO.File]::ReadAllBytes($f.FullName)
                        $len = [Math]::Min($raw.Length, $MaxBytesToRead)
                        $content = [System.Text.Encoding]::GetEncoding(28591).GetString($raw, 0, $len)
                        if ($raw.Length -gt $len) { $content += "..." }
                        if (Test-SuspiciousScriptContent -Content $content -Ext $f.Extension) {
                            $detections += @{
                                Path = $f.FullName
                                Length = $f.Length
                                Extension = $f.Extension
                                Risk = "High"
                            }
                        }
                    } catch { }
                }
                if ($totalScanned -ge $MaxFiles) { break }
            }
            if ($totalScanned -ge $MaxFiles) { break }
        }

        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2095 `
                    -Message "ScriptContentScan: Suspicious script $($d.Path)" -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\ScriptContentScan_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Path)|$($_.Risk)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) suspicious scripts"
        } else {
            Write-Output "STATS:$ModuleName`:Scanned $totalScanned files OK"
        }
        return $detections.Count
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
        return 0
    }
}

function Start-Module {
    param([hashtable]$Config)
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                Invoke-ScriptContentScan | Out-Null
                $LastTick = $now
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{} }
