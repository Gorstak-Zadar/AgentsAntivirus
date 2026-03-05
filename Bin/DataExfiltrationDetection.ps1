# Data Exfiltration Detection Module
# Comprehensive data exfiltration detection beyond DNS

param([hashtable]$ModuleConfig)

$ModuleName = "DataExfiltrationDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }
$BaselineTransfer = @{}

function Invoke-DataExfiltrationDetection {
    $detections = @()
    
    try {
        # Check for large outbound data transfers
        try {
            $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)' }
            
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $procConns = $connections | Where-Object { $_.OwningProcess -eq $proc.Id }
                    
                    if ($procConns.Count -gt 0) {
                        # Check network statistics
                        $netStats = Get-Counter "\Process($($proc.ProcessName))\IO Data Bytes/sec" -ErrorAction SilentlyContinue
                        if ($netStats) {
                            $bytesPerSec = $netStats.CounterSamples[0].CookedValue
                            
                            # Large outbound transfer
                            if ($bytesPerSec -gt 1MB) {
                                $baselineKey = $proc.ProcessName
                                $baseline = if ($BaselineTransfer.ContainsKey($baselineKey)) { $BaselineTransfer[$baselineKey] } else { 0 }
                                
                                if ($bytesPerSec -gt $baseline * 2 -and $bytesPerSec -gt 1MB) {
                                    $detections += @{
                                        ProcessId = $proc.Id
                                        ProcessName = $proc.ProcessName
                                        BytesPerSecond = [Math]::Round($bytesPerSec / 1MB, 2)
                                        ConnectionCount = $procConns.Count
                                        Type = "Large Outbound Data Transfer"
                                        Risk = "High"
                                    }
                                }
                                
                                $BaselineTransfer[$baselineKey] = $bytesPerSec
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for file uploads to cloud storage/suspicious domains
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.ProcessName -match 'curl|wget|powershell|certutil|bitsadmin' }
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    
                    if ($procObj.CommandLine) {
                        $uploadPatterns = @(
                            'upload|PUT|POST',
                            'dropbox|google.*drive|onedrive|mega|wetransfer',
                            'pastebin|github|paste.*bin',
                            'http.*upload|ftp.*put',
                            '-OutFile.*http',
                            'Invoke-WebRequest.*-Method.*Put'
                        )
                        
                        foreach ($pattern in $uploadPatterns) {
                            if ($procObj.CommandLine -match $pattern -and 
                                $procObj.CommandLine -notmatch 'download|get|GET') {
                                $detections += @{
                                    ProcessId = $proc.Id
                                    ProcessName = $proc.ProcessName
                                    CommandLine = $procObj.CommandLine
                                    Pattern = $pattern
                                    Type = "File Upload to External Service"
                                    Risk = "High"
                                }
                                break
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for clipboard with large data (possible exfiltration)
        try {
            Add-Type -AssemblyName System.Windows.Forms
            
            if ([System.Windows.Forms.Clipboard]::ContainsText()) {
                $clipboardText = [System.Windows.Forms.Clipboard]::GetText()
                
                if ($clipboardText.Length -gt 50000) {
                    # Large clipboard content
                    $detections += @{
                        ClipboardSize = $clipboardText.Length
                        Type = "Large Clipboard Content (Possible Exfiltration)"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        # Check for processes accessing many files then connecting externally
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                    $fileHandles = $handles | Where-Object { $_.Name -like "*.txt" -or $_.Name -like "*.doc*" -or $_.Name -like "*.pdf" -or $_.Name -like "*.xls*" }
                    
                    if ($fileHandles.Count -gt 20) {
                        $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                            Where-Object { 
                                $_.State -eq "Established" -and 
                                $_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)'
                            }
                        
                        if ($conns.Count -gt 0) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                FileHandleCount = $fileHandles.Count
                                ExternalConnections = $conns.Count
                                Type = "File Access Followed by External Connection"
                                Risk = "High"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for processes reading sensitive files then connecting externally
        try {
            $sensitivePaths = @(
                "$env:USERPROFILE\Documents",
                "$env:USERPROFILE\Desktop",
                "$env:APPDATA\..\Local\Credentials"
            )
            
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    foreach ($sensitivePath in $sensitivePaths) {
                        if (Test-Path $sensitivePath) {
                            $files = Get-ChildItem -Path $sensitivePath -File -ErrorAction SilentlyContinue |
                                Where-Object { (Get-Date) - $_.LastAccessTime -lt [TimeSpan]::FromMinutes(5) }
                            
                            if ($files.Count -gt 5) {
                                $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                                    Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -notmatch '^(10\.|192\.168\.)' }
                                
                                if ($conns.Count -gt 0) {
                                    $detections += @{
                                        ProcessId = $proc.Id
                                        ProcessName = $proc.ProcessName
                                        SensitiveFilesAccessed = $files.Count
                                        ExternalConnections = $conns.Count
                                        Type = "Sensitive File Access Followed by External Connection"
                                        Risk = "Critical"
                                    }
                                    break
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2040 `
                    -Message "DATA EXFILTRATION: $($detection.Type) - $($detection.ProcessName -or 'System')"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\DataExfiltration_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) data exfiltration indicators"
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
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-DataExfiltrationDetection
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
    Start-Module -Config @{ TickInterval = 30 }
}
