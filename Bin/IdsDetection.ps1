# IDS Detection
# Command-line IDS patterns (meterpreter, certutil -urlcache, etc.)

param([hashtable]$ModuleConfig)

$ModuleName = "IdsDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

$Patterns = @(
    @{ Pattern = "meterpreter"; Desc = "Metasploit meterpreter" }
    @{ Pattern = "certutil\s+-urlcache"; Desc = "Certutil download" }
    @{ Pattern = "bitsadmin\s+/transfer"; Desc = "Bitsadmin download" }
    @{ Pattern = "powershell\s+-enc"; Desc = "Base64 encoded PS" }
    @{ Pattern = "powershell\s+-w\s+hidden"; Desc = "Hidden window PS" }
    @{ Pattern = "invoke-expression"; Desc = "IEX usage" }
    @{ Pattern = "iex\s*\("; Desc = "IEX usage" }
    @{ Pattern = "downloadstring"; Desc = "DownloadString" }
    @{ Pattern = "downloadfile"; Desc = "DownloadFile" }
    @{ Pattern = "webclient"; Desc = "WebClient" }
    @{ Pattern = "net\.webclient"; Desc = "Net.WebClient" }
    @{ Pattern = "bypass.*-executionpolicy"; Desc = "Execution policy bypass" }
    @{ Pattern = "wmic\s+process\s+call\s+create"; Desc = "WMI process creation" }
    @{ Pattern = "reg\s+add.*HKLM.*Run"; Desc = "Registry Run key" }
    @{ Pattern = "schtasks\s+/create"; Desc = "Scheduled task creation" }
    @{ Pattern = "netsh\s+firewall"; Desc = "Firewall modification" }
    @{ Pattern = "sc\s+create"; Desc = "Service creation" }
    @{ Pattern = "rundll32.*\.dll"; Desc = "Rundll32 DLL" }
    @{ Pattern = "regsvr32\s+.*/s"; Desc = "Regsvr32 silent" }
    @{ Pattern = "mshta\s+http"; Desc = "Mshta remote script" }
)

function Invoke-IdsScan {
    $detections = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine
        foreach ($proc in $processes) {
            $cmd = [string]$proc.CommandLine
            foreach ($p in $Patterns) {
                if ($cmd -match $p.Pattern) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = $p.Pattern
                        Description = $p.Desc
                        CommandLine = $cmd.Substring(0, [Math]::Min(500, $cmd.Length))
                    }
                    break
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2095 -Message "IDS: $($d.Description) - $($d.ProcessName) PID:$($d.ProcessId)" -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\ids_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Description)|$($_.ProcessName)|PID:$($_.ProcessId)" | Add-Content -Path $logPath }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) IDS matches"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
}

function Start-Module {
    param([hashtable]$Config)
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-IdsScan
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 60 } }
