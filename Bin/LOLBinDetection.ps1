# Living-Off-The-Land Binary Detection
# Detects legitimate tools used maliciously

param([hashtable]$ModuleConfig)

$ModuleName = "LOLBinDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }
$LOLBinPatterns = @{
    "cmd.exe" = @("\/c.*certutil|powershell|bitsadmin|regsvr32")
    "powershell.exe" = @("-nop.*-w.*hidden|-EncodedCommand|-ExecutionPolicy.*Bypass")
    "wmic.exe" = @("process.*call.*create")
    "mshta.exe" = @("http|https|\.hta")
    "rundll32.exe" = @("javascript:|\.dll.*\,")
    "regsvr32.exe" = @("\/s.*\/i.*http|\.sct")
    "certutil.exe" = @("-urlcache|-decode|\.exe")
    "bitsadmin.exe" = @("/transfer|/rawreturn")
    "schtasks.exe" = @("/create.*/tn.*http|/create.*/tr.*powershell")
    "msbuild.exe" = @("\.xml.*http|\.csproj.*http")
    "csc.exe" = @("\.cs.*http")
}
$DetectionCount = 0

function Get-RunningProcesses {
    try {
        return Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, CreationDate, ParentProcessId
    } catch {
        return @()
    }
}

function Test-LOLBinCommandLine {
    param(
        [string]$ProcessName,
        [string]$CommandLine
    )
    
    if ([string]::IsNullOrEmpty($CommandLine)) { return $null }
    
    $processNameLower = $ProcessName.ToLower()
    $cmdLineLower = $CommandLine.ToLower()
    
    if ($LOLBinPatterns.ContainsKey($processNameLower)) {
        foreach ($pattern in $LOLBinPatterns[$processNameLower]) {
            if ($cmdLineLower -match $pattern) {
                return @{
                    Process = $ProcessName
                    CommandLine = $CommandLine
                    Pattern = $pattern
                    Risk = "High"
                }
            }
        }
    }
    
    # Additional heuristics
    if ($cmdLineLower -match 'powershell.*-encodedcommand' -and 
        $cmdLineLower.Length -gt 500) {
        return @{
            Process = $ProcessName
            CommandLine = $CommandLine
            Pattern = "Long encoded PowerShell command"
            Risk = "High"
        }
    }
    
    if ($cmdLineLower -match '(http|https)://[^\s]+' -and 
        $processNameLower -in @('cmd.exe','rundll32.exe','mshta.exe')) {
        return @{
            Process = $ProcessName
            CommandLine = $CommandLine
            Pattern = "Network download from LOLBin"
            Risk = "High"
        }
    }
    
    return $null
}

function Invoke-LOLBinScan {
    $detections = @()
    $processes = Get-RunningProcesses
    
    foreach ($proc in $processes) {
        $result = Test-LOLBinCommandLine -ProcessName $proc.Name -CommandLine $proc.CommandLine
        if ($result) {
            $detections += @{
                ProcessId = $proc.ProcessId
                ProcessName = $proc.Name
                CommandLine = $proc.CommandLine
                Pattern = $result.Pattern
                Risk = $result.Risk
                ParentProcessId = $proc.ParentProcessId
                CreationDate = $proc.CreationDate
            }
        }
    }
    
    if ($detections.Count -gt 0) {
        $script:DetectionCount += $detections.Count
        
        foreach ($detection in $detections) {
            Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2002 `
                -Message "LOLBIN DETECTED: $($detection.ProcessName) (PID: $($detection.ProcessId)) - $($detection.Pattern)"
            
            # Log details
            $logPath = "$env:ProgramData\Antivirus\Logs\LOLBinDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($detection.ProcessId)|$($detection.ProcessName)|$($detection.Pattern)|$($detection.CommandLine)" | 
                Add-Content -Path $logPath
        }
        
        Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) LOLBin instances"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-LOLBinScan
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Scanned processes, Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{ TickInterval = 30 }
}
