# OptimizedConfig.ps1 - Shared configuration and adaptive performance helpers
# Provides CPU-aware scheduling to prevent EDR from degrading system responsiveness

$script:CPULoadCache = @{ Value = 0; Updated = [datetime]::MinValue }
$script:CPULoadCacheTTL = 5

function Get-CPULoad {
    $now = Get-Date
    if (($now - $script:CPULoadCache.Updated).TotalSeconds -lt $script:CPULoadCacheTTL) {
        return $script:CPULoadCache.Value
    }
    try {
        $load = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
            Measure-Object -Property LoadPercentage -Average).Average
        if ($null -eq $load) { $load = 0 }
    } catch {
        $load = 0
    }
    $script:CPULoadCache.Value = $load
    $script:CPULoadCache.Updated = $now
    return $load
}

function Test-CPULoadThreshold {
    param([int]$Threshold = 80)
    return (Get-CPULoad) -lt $Threshold
}

function Get-TickInterval {
    param([int]$BaseInterval)
    $load = Get-CPULoad
    if ($load -gt 90) { return [math]::Min($BaseInterval * 4, 3600) }
    if ($load -gt 75) { return [math]::Min($BaseInterval * 2, 1800) }
    if ($load -gt 50) { return [int]($BaseInterval * 1.5) }
    return $BaseInterval
}

function Get-LoopSleep {
    param([int]$BaseSleep = 5)
    $load = Get-CPULoad
    if ($load -gt 90) { return [math]::Min($BaseSleep * 3, 30) }
    if ($load -gt 75) { return [math]::Min($BaseSleep * 2, 15) }
    return $BaseSleep
}

function Get-DataPath {
    $p = "$env:ProgramData\Antivirus\Data"
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    return $p
}

function Get-LogPath {
    $p = "$env:ProgramData\Antivirus\Logs"
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    return $p
}

function Write-ModuleLog {
    param(
        [string]$Module,
        [string]$Message,
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logFile = Join-Path (Get-LogPath) "$($Module)_$(Get-Date -Format 'yyyy-MM-dd').log"
    "[$ts] [$Level] $Message" | Add-Content -Path $logFile -ErrorAction SilentlyContinue
}
