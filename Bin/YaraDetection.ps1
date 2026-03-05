# YARA Detection
# Runs yara.exe against suspicious files (if present)

param([hashtable]$ModuleConfig)

$ModuleName = "YaraDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 120 }
$YaraPaths = @("$env:ProgramFiles\Yara\yara64.exe", "$env:ProgramFiles (x86)\Yara\yara.exe", "yara.exe", "yara64.exe")
$RulesPaths = @("$env:ProgramData\Antivirus\Yara", "$env:ProgramData\Antivirus\Rules", "$PSScriptRoot\YaraRules")
$ScanPaths = @("$env:Temp", "$env:TEMP", "$env:SystemRoot\Temp")

function Get-YaraExe {
    foreach ($p in $YaraPaths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Get-RulesPath {
    foreach ($p in $RulesPaths) {
        if (Test-Path $p) {
            $rules = Get-ChildItem -Path $p -Filter *.yar -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($rules) { return $rules.Directory.FullName }
        }
    }
    return $null
}

function Invoke-YaraScan {
    $yara = Get-YaraExe
    if (-not $yara) {
        return 0
    }
    
    $rulesDir = Get-RulesPath
    if (-not $rulesDir) {
        return 0
    }
    
    $detections = @()
    foreach ($base in $ScanPaths) {
        if (-not (Test-Path $base)) { continue }
        try {
            $files = Get-ChildItem -Path $base -Include *.exe, *.dll, *.ps1 -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 100
            foreach ($f in $files) {
                try {
                    $out = & $yara -r "$rulesDir\*.yar" $f.FullName 2>&1
                    if ($out -and $out -match '\S') {
                        $detections += @{
                            File = $f.FullName
                            Match = ($out | Select-Object -First 5) -join "; "
                        }
                    }
                } catch { }
            }
        } catch { }
    }
    
    if ($detections.Count -gt 0) {
        foreach ($d in $detections) {
            Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2096 -Message "YARA: $($d.File) - $($d.Match)" -ErrorAction SilentlyContinue
        }
        $logPath = "$env:ProgramData\Antivirus\Logs\yara_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
        $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.File)|$($_.Match)" | Add-Content -Path $logPath }
        Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) YARA matches"
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
                Invoke-YaraScan | Out-Null
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 120 } }
