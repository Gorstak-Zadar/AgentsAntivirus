# Clipboard Monitoring Module
# Monitors clipboard for sensitive data

param([hashtable]$ModuleConfig)

$ModuleName = "ClipboardMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 10 }

function Invoke-ClipboardMonitoring {
    $detections = @()
    
    try {
        # Monitor clipboard content
        Add-Type -AssemblyName System.Windows.Forms
        
        if ([System.Windows.Forms.Clipboard]::ContainsText()) {
            $clipboardText = [System.Windows.Forms.Clipboard]::GetText()
            
            if (-not [string]::IsNullOrEmpty($clipboardText)) {
                # Check for sensitive data patterns
                $sensitivePatterns = @(
                    @{Pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'; Type = 'Email Address'},
                    @{Pattern = '\b\d{3}-\d{2}-\d{4}\b'; Type = 'SSN'},
                    @{Pattern = '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'; Type = 'Credit Card'},
                    @{Pattern = '(?i)(password|passwd|pwd|secret|api[_-]?key|token|bearer)'; Type = 'Password/Token'},
                    @{Pattern = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'; Type = 'IP Address'},
                    @{Pattern = '(?i)(https?://[^\s]+)'; Type = 'URL'}
                )
                
                foreach ($pattern in $sensitivePatterns) {
                    if ($clipboardText -match $pattern.Pattern) {
                        $matches = [regex]::Matches($clipboardText, $pattern.Pattern)
                        
                        if ($matches.Count -gt 0) {
                            $detections += @{
                                Type = "Sensitive Data in Clipboard"
                                DataType = $pattern.Type
                                MatchCount = $matches.Count
                                Risk = if ($pattern.Type -match 'Password|SSN|Credit Card') { "High" } else { "Medium" }
                            }
                        }
                    }
                }
                
                # Check for large clipboard content (possible exfiltration)
                if ($clipboardText.Length -gt 10000) {
                    $detections += @{
                        Type = "Large Clipboard Content"
                        ContentLength = $clipboardText.Length
                        Risk = "Medium"
                    }
                }
                
                # Check for base64 encoded content
                if ($clipboardText -match '^[A-Za-z0-9+/]+={0,2}$' -and $clipboardText.Length -gt 100) {
                    try {
                        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($clipboardText))
                        if ($decoded.Length -gt 0) {
                            $detections += @{
                                Type = "Base64 Encoded Content in Clipboard"
                                EncodedLength = $clipboardText.Length
                                DecodedLength = $decoded.Length
                                Risk = "Medium"
                            }
                        }
                    } catch { }
                }
            }
        }
        
        # Check for processes accessing clipboard
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'clipboard|clip'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Exclude legitimate processes
                        $legitProcesses = @("explorer.exe", "dwm.exe", "mstsc.exe")
                        if ($proc.ProcessName -notin $legitProcesses) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                Type = "Process Accessing Clipboard"
                                Risk = "Medium"
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
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2018 `
                    -Message "CLIPBOARD MONITORING: $($detection.Type) - $($detection.DataType -or $detection.ProcessName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Clipboard_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.DataType -or $_.ProcessName)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) clipboard anomalies"
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
                $count = Invoke-ClipboardMonitoring
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
    Start-Module -Config @{ TickInterval = 10 }
}
