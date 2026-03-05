# Attack Tools Detection
# Detects Mimikatz, Cobalt Strike, Metasploit, etc.

param([hashtable]$ModuleConfig)

$ModuleName = "AttackToolsDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 90 }

$AttackTools = @("mimikatz", "pwdump", "procdump", "wce", "gsecdump", "cain", "john", "hashcat", "hydra", "medusa", "nmap", "metasploit", "armitage", "cobalt")

function Invoke-AttackToolsScan {
    $detections = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine
        foreach ($proc in $processes) {
            $name = ([string]$proc.Name).ToLower()
            $cmd = ([string]$proc.CommandLine).ToLower()
            foreach ($tool in $AttackTools) {
                if ($name -like "*$tool*" -or $cmd -like "*$tool*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $proc.CommandLine
                        Tool = $tool
                        Type = "Attack Tool Detected"
                        Risk = "Critical"
                    }
                    break
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2092 -Message "ATTACK TOOL: $($d.Tool) - $($d.ProcessName) (PID: $($d.ProcessId))" -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\attack_tools_detection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Tool)|$($_.ProcessName)|PID:$($_.ProcessId)" | Add-Content -Path $logPath }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) attack tools"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
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
                Invoke-AttackToolsScan | Out-Null
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 90 } }
