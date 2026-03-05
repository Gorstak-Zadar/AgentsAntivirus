# AMSI Bypass Detection Module
# Detects attempts to bypass Windows AMSI - Optimized for low resource usage

param([hashtable]$ModuleConfig)

. "$PSScriptRoot\OptimizedConfig.ps1"

$ModuleName = "AMSIBypassDetection"
$script:LastTick = Get-Date
$TickInterval = Get-TickInterval -ModuleName $ModuleName

function Invoke-AMSIBypassScan {
    $detections = @()
    
    # Check for AMSI bypass techniques in running processes
    try {
        $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
        $processes = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*powershell*" -or $_.Name -like "*wscript*" -or $_.Name -like "*cscript*" } | Select-Object -First $maxProcs
        
        foreach ($proc in $processes) {
            $cmdLine = $proc.CommandLine
            if ([string]::IsNullOrEmpty($cmdLine)) { continue }
            
            # Enhanced AMSI bypass patterns
            $bypassPatterns = @(
                '[Ref].Assembly.GetType.*System.Management.Automation.AmsiUtils',
                '[Ref].Assembly.GetType.*AmsiUtils',
                'AmsiScanBuffer',
                'amsiInitFailed',
                'Bypass',
                'amsi.dll',
                'S`y`s`t`e`m.Management.Automation',
                'Hacking',
                'AMSI',
                'amsiutils',
                'amsiInitFailed',
                'Context',
                'AmsiContext',
                'AMSI_RESULT_CLEAN',
                'PatchAmsi',
                'DisableAmsi',
                'ForceAmsi',
                'Remove-Amsi',
                'Invoke-AmsiBypass',
                'AMSI.*bypass',
                'bypass.*AMSI',
                '-nop.*-w.*hidden.*-enc',
                'amsi.*off',
                'amsi.*disable',
                'Set-Amsi',
                'Override.*AMSI'
            )
            
            foreach ($pattern in $bypassPatterns) {
                if ($cmdLine -match $pattern) {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $cmdLine
                        BypassPattern = $pattern
                        Risk = "Critical"
                    }
                    break
                }
            }
            
            # Check for obfuscated AMSI bypass (base64, hex, etc.)
            if ($cmdLine -match '-enc|-encodedcommand' -and $cmdLine.Length -gt 500) {
                # Long encoded command - try to decode
                try {
                    $encodedPart = $cmdLine -split '-enc\s+' | Select-Object -Last 1 -ErrorAction SilentlyContinue
                    if ($encodedPart) {
                        $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedPart.Trim()))
                        if ($decoded -match 'amsi|AmsiScanBuffer|bypass' -or $decoded.Length -gt 1000) {
                            $detections += @{
                                ProcessId = $proc.ProcessId
                                ProcessName = $proc.Name
                                CommandLine = $cmdLine
                                BypassPattern = "Obfuscated AMSI Bypass (Encoded)"
                                DecodedLength = $decoded.Length
                                Risk = "Critical"
                            }
                        }
                    }
                } catch { }
            }
        }
        
        # Check PowerShell script blocks in memory
        try {
            $psProcesses = Get-Process -Name "powershell*","pwsh*" -ErrorAction SilentlyContinue
            foreach ($psProc in $psProcesses) {
                # Check for AMSI-related .NET assemblies loaded
                $modules = $psProc.Modules | Where-Object {
                    $_.ModuleName -match 'amsi|System.Management.Automation'
                }
                
                if ($modules.Count -gt 0) {
                    # Check Event Log for AMSI script block logging
                    try {
                        $psEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue -MaxEvents 50 |
                            Where-Object {
                                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5) -and
                                ($_.Message -match 'amsi|bypass|AmsiScanBuffer' -or $_.Message.Length -gt 5000)
                            }
                        
                        if ($psEvents.Count -gt 0) {
                            foreach ($event in $psEvents) {
                                $detections += @{
                                    ProcessId = $psProc.Id
                                    ProcessName = $psProc.ProcessName
                                    Type = "AMSI Bypass in PowerShell Script Block"
                                    Message = $event.Message.Substring(0, [Math]::Min(500, $event.Message.Length))
                                    TimeCreated = $event.TimeCreated
                                    Risk = "Critical"
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        # Check Event Log for AMSI events
        try {
            $amsiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,1118} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $amsiEvents) {
                if ($event.Message -match 'AmsiScanBuffer|bypass|blocked') {
                    $detections += @{
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for AMSI registry tampering
        try {
            $amsiKey = "HKLM:\SOFTWARE\Microsoft\AMSI"
            if (Test-Path $amsiKey) {
                $amsiValue = Get-ItemProperty -Path $amsiKey -ErrorAction SilentlyContinue
                if ($amsiValue -and $amsiValue.DisableAMSI) {
                    $detections += @{
                        Type = "Registry Tampering"
                        Path = $amsiKey
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2004 `
                    -Message "AMSI BYPASS DETECTED: $($detection.ProcessName -or $detection.Type) - $($detection.BypassPattern -or $detection.Message)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\AMSIBypass_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.BypassPattern -or $_.Message)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) AMSI bypass attempts"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    $loopSleep = Get-LoopSleep
    $maxProcs = Get-ScanLimit -LimitName "MaxProcesses"
    
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 90)  # Longer initial delay
    
    while ($true) {
        try {
            # CPU throttling - skip scan if CPU load is too high
            if (Test-CPULoadThreshold) {
                $cpuLoad = Get-CPULoad
                Write-Output "STATS:$ModuleName`:CPU load too high ($cpuLoad%), skipping scan"
                Start-Sleep -Seconds ($loopSleep * 2)  # Sleep longer when CPU is high
                continue
            }
            
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-AMSIBypassScan
                $script:LastTick = $now
                Write-Output "STATS:$ModuleName`:Detections=$count"
            }
            Start-Sleep -Seconds $loopSleep
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 120  # Longer sleep on error
        }
    }
}

if (-not $ModuleConfig) {
    Start-Module -Config @{}
}
