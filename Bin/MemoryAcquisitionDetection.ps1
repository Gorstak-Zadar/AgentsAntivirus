# Memory Acquisition Detection
# Detects WinPmem, pmem, FTK Imager, etc.

param([hashtable]$ModuleConfig)

$ModuleName = "MemoryAcquisitionDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 90 }

$ProcessPatterns = @("winpmem", "pmem", "osxpmem", "aff4imager", "winpmem_mini", "memdump", "rawdump")
$CmdPatterns = @("winpmem", "pmem", "\.\pmem", "/dev/pmem", ".aff4", "-o .raw", "-o .aff4", "image.raw", "memory.raw", "physical memory", "memory acquisition", "physicalmemory")

function Invoke-MemoryAcquisitionScan {
    $detections = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, CommandLine, ExecutablePath
        foreach ($proc in $processes) {
            $name = ([string]$proc.Name).ToLower()
            $cmd = ([string]$proc.CommandLine) + " " + ([string]$proc.ExecutablePath)
            
            foreach ($pat in $ProcessPatterns) {
                if ($name -like "*$pat*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = $pat
                        Type = "Memory Acquisition Tool"
                        Risk = "Critical"
                    }
                    break
                }
            }
            if ($detections[-1].ProcessId -eq $proc.ProcessId) { continue }
            
            foreach ($pat in $CmdPatterns) {
                if ($cmd -like "*$pat*") {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        Pattern = "cmd:$pat"
                        Type = "Memory Acquisition (cmd)"
                        Risk = "Critical"
                    }
                    break
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2093 -Message "MEMORY ACQUISITION: $($d.Pattern) - $($d.ProcessName) (PID: $($d.ProcessId))" -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\memory_acquisition_detections_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.ProcessName)|PID:$($_.ProcessId)" | Add-Content -Path $logPath }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) memory acquisition indicators"
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
                Invoke-MemoryAcquisitionScan | Out-Null
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 90 } }
