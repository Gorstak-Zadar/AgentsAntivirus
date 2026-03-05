# Browser Extension Monitoring Module
# Monitors browser extensions for malicious activity

param([hashtable]$ModuleConfig)

$ModuleName = "BrowserExtensionMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-BrowserExtensionMonitoring {
    $detections = @()
    
    try {
        # Check Chrome extensions
        $chromeExtensionsPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        if (Test-Path $chromeExtensionsPath) {
            $chromeExts = Get-ChildItem -Path $chromeExtensionsPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $chromeExts) {
                $manifestPath = Join-Path $ext.FullName "*\manifest.json"
                $manifests = Get-ChildItem -Path $manifestPath -ErrorAction SilentlyContinue
                
                foreach ($manifest in $manifests) {
                    try {
                        $manifestContent = Get-Content $manifest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        
                        # Check for suspicious permissions
                        $suspiciousPermissions = @("all_urls", "tabs", "cookies", "history", "downloads", "webRequest", "webRequestBlocking")
                        $hasSuspiciousPerms = $false
                        
                        if ($manifestContent.permissions) {
                            foreach ($perm in $manifestContent.permissions) {
                                if ($perm -in $suspiciousPermissions) {
                                    $hasSuspiciousPerms = $true
                                    break
                                }
                            }
                        }
                        
                        # Check for unsigned extensions
                        $isSigned = $manifestContent.key -ne $null
                        
                        if ($hasSuspiciousPerms -or -not $isSigned) {
                            $detections += @{
                                Browser = "Chrome"
                                ExtensionId = $ext.Name
                                ExtensionName = $manifestContent.name
                                ManifestPath = $manifest.FullName
                                HasSuspiciousPermissions = $hasSuspiciousPerms
                                IsSigned = $isSigned
                                Type = "Suspicious Chrome Extension"
                                Risk = if ($hasSuspiciousPerms) { "High" } else { "Medium" }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        # Check Edge extensions
        $edgeExtensionsPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
        if (Test-Path $edgeExtensionsPath) {
            $edgeExts = Get-ChildItem -Path $edgeExtensionsPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $edgeExts) {
                $manifestPath = Join-Path $ext.FullName "*\manifest.json"
                $manifests = Get-ChildItem -Path $manifestPath -ErrorAction SilentlyContinue
                
                foreach ($manifest in $manifests) {
                    try {
                        $manifestContent = Get-Content $manifest.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                        
                        if ($manifestContent.permissions) {
                            $suspiciousPerms = $manifestContent.permissions | Where-Object {
                                $_ -in @("all_urls", "tabs", "cookies", "webRequest")
                            }
                            
                            if ($suspiciousPerms.Count -gt 0) {
                                $detections += @{
                                    Browser = "Edge"
                                    ExtensionId = $ext.Name
                                    ExtensionName = $manifestContent.name
                                    SuspiciousPermissions = $suspiciousPerms -join ','
                                    Type = "Suspicious Edge Extension"
                                    Risk = "Medium"
                                }
                            }
                        }
                    } catch {
                        continue
                    }
                }
            }
        }
        
        # Check Firefox extensions
        $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfilesPath) {
            $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue
            
            foreach ($profile in $profiles) {
                $extensionsPath = Join-Path $profile.FullName "extensions"
                if (Test-Path $extensionsPath) {
                    $firefoxExts = Get-ChildItem -Path $extensionsPath -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -eq ".xpi" -or $_.Extension -eq "" }
                    
                    foreach ($ext in $firefoxExts) {
                        $detections += @{
                            Browser = "Firefox"
                            ExtensionPath = $ext.FullName
                            Type = "Firefox Extension Detected"
                            Risk = "Low"
                        }
                    }
                }
            }
        }
        
        # Check for browser processes with unusual activity
        try {
            $browserProcs = Get-Process -ErrorAction SilentlyContinue | 
                Where-Object { $_.ProcessName -match 'chrome|edge|firefox|msedge' }
            
            foreach ($proc in $browserProcs) {
                try {
                    $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                        Where-Object { $_.State -eq "Established" }
                    
                    # Check for connections to suspicious domains
                    $remoteIPs = $conns.RemoteAddress | Select-Object -Unique
                    
                    foreach ($ip in $remoteIPs) {
                        try {
                            $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
                            
                            $suspiciousDomains = @(".onion", ".bit", ".i2p", "pastebin", "githubusercontent")
                            foreach ($domain in $suspiciousDomains) {
                                if ($hostname -like "*$domain*") {
                                    $detections += @{
                                        BrowserProcess = $proc.ProcessName
                                        ProcessId = $proc.Id
                                        ConnectedDomain = $hostname
                                        Type = "Browser Connecting to Suspicious Domain"
                                        Risk = "Medium"
                                    }
                                }
                            }
                        } catch { }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2020 `
                    -Message "BROWSER EXTENSION: $($detection.Type) - $($detection.ExtensionName -or $detection.BrowserProcess)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\BrowserExtension_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ExtensionName -or $_.BrowserProcess)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) browser extension anomalies"
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
                $count = Invoke-BrowserExtensionMonitoring
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
