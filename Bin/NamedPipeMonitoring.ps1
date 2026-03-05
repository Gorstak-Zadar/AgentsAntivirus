# Named Pipe Monitoring Module
# Monitors named pipes for malicious activity

param([hashtable]$ModuleConfig)

$ModuleName = "NamedPipeMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-NamedPipeMonitoring {
    $detections = @()
    
    try {
        # Get named pipes using WMI
        $pipes = Get-CimInstance Win32_NamedPipe -ErrorAction SilentlyContinue
        
        # Check for suspicious named pipes
        $suspiciousPatterns = @(
            "paexec",
            "svchost",
            "lsass",
            "spoolsv",
            "psexec",
            "mimikatz",
            "impacket"
        )
        
        foreach ($pipe in $pipes) {
            $pipeNameLower = $pipe.Name.ToLower()
            
            foreach ($pattern in $suspiciousPatterns) {
                if ($pipeNameLower -match $pattern) {
                    $detections += @{
                        PipeName = $pipe.Name
                        Pattern = $pattern
                        Type = "Suspicious Named Pipe Pattern"
                        Risk = "Medium"
                    }
                    break
                }
            }
            
            # Check for pipes with unusual names (random characters)
            if ($pipe.Name -match '^[A-Za-z0-9]{32,}$' -and 
                $pipe.Name -notmatch 'microsoft|windows|system') {
                $detections += @{
                    PipeName = $pipe.Name
                    Type = "Named Pipe with Random-Like Name"
                    Risk = "Low"
                }
            }
        }
        
        # Check for processes creating named pipes
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procPipes = $pipes | Where-Object {
                        $_.Instances -gt 0
                    }
                    
                    # Check for processes creating many named pipes
                    $pipeCount = ($procPipes | Measure-Object).Count
                    
                    if ($pipeCount -gt 10 -and 
                        $proc.ProcessName -notin @("svchost.exe", "spoolsv.exe", "services.exe")) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            PipeCount = $pipeCount
                            Type = "Process Creating Many Named Pipes"
                            Risk = "Medium"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check Event Log for named pipe errors
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object { 
                    $_.Message -match 'named.*pipe|pipe.*error|pipe.*failed'
                }
            
            $pipeErrors = $events | Where-Object {
                $_.LevelDisplayName -eq "Error"
            }
            
            if ($pipeErrors.Count -gt 5) {
                $detections += @{
                    EventCount = $pipeErrors.Count
                    Type = "Excessive Named Pipe Errors"
                    Risk = "Low"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Information -EventId 2028 `
                    -Message "NAMED PIPE MONITORING: $($detection.Type) - $($detection.PipeName -or $detection.ProcessName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\NamedPipe_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.PipeName -or $_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) named pipe anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Active pipes=$($pipes.Count)"
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
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-NamedPipeMonitoring
                $LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{ TickInterval = 60 }
}
