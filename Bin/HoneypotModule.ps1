# Honeypot Module
# Creates decoy files and processes to detect unauthorized access

param([hashtable]$ModuleConfig)

$ModuleName = "HoneypotModule"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 300 }
$HoneypotFiles = @()
$HoneypotPaths = @(
    "$env:USERPROFILE\Desktop\passwords.txt",
    "$env:USERPROFILE\Documents\credentials.xlsx",
    "$env:USERPROFILE\Documents\credit_cards.txt",
    "$env:USERPROFILE\Desktop\private_keys.txt",
    "$env:APPDATA\credentials.db",
    "$env:USERPROFILE\Documents\financial_data.xlsx"
)

function Initialize-Honeypots {
    try {
        foreach ($honeypotPath in $HoneypotPaths) {
            $dir = Split-Path -Parent $honeypotPath
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            }
            
            if (-not (Test-Path $honeypotPath)) {
                # Create honeypot file with fake but realistic content
                $content = switch -Wildcard ([System.IO.Path]::GetFileName($honeypotPath)) {
                    "*password*" { "FAKE_PASSWORD_FILE_DO_NOT_USE`r`nusername: admin`r`npassword: fake_password_123`r`nLastModified: $(Get-Date -Format 'yyyy-MM-dd')" }
                    "*credential*" { "FAKE_CREDENTIAL_FILE_DO_NOT_USE`r`nAccount: fake_account`r`nPassword: fake_pass_123`r`nCreated: $(Get-Date -Format 'yyyy-MM-dd')" }
                    "*credit*" { "FAKE_CREDIT_CARD_FILE_DO_NOT_USE`r`nCard: 4111-1111-1111-1111`r`nCVV: 123`r`nExpiry: 12/25" }
                    "*key*" { "FAKE_PRIVATE_KEY_FILE_DO_NOT_USE`r`n-----BEGIN FAKE RSA PRIVATE KEY-----`r`nFAKE_KEY_DATA`r`n-----END FAKE RSA PRIVATE KEY-----" }
                    "*financial*" { "FAKE_FINANCIAL_DATA_FILE_DO_NOT_USE`r`nAccount: 123456789`r`nBalance: $0.00`r`nTransaction: None" }
                    default { "FAKE_FILE_DO_NOT_USE - Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
                }
                
                Set-Content -Path $honeypotPath -Value $content -ErrorAction SilentlyContinue
                
                # Mark as honeypot with file attribute
                try {
                    $file = Get-Item $honeypotPath -ErrorAction Stop
                    $file.Attributes = $file.Attributes -bor [System.IO.FileAttributes]::Hidden
                } catch { }
                
                $HoneypotFiles += @{
                    Path = $honeypotPath
                    Created = Get-Date
                    LastAccessed = $null
                    AccessCount = 0
                }
                
                Write-Output "STATS:$ModuleName`:Created honeypot: $honeypotPath"
            }
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:Failed to initialize honeypots: $_"
    }
}

function Invoke-HoneypotMonitoring {
    $detections = @()
    
    try {
        # Check honeypot file access
        foreach ($honeypot in $HoneypotFiles) {
            $honeypotPath = $honeypot.Path
            
            if (Test-Path $honeypotPath) {
                try {
                    $file = Get-Item $honeypotPath -ErrorAction Stop
                    $lastAccess = $file.LastAccessTime
                    
                    # Check if file was accessed recently
                    if ($honeypot.LastAccessed -and $lastAccess -gt $honeypot.LastAccessed) {
                        $honeypot.AccessCount++
                        
                        # Detect unauthorized access
                        if ($honeypot.AccessCount -gt 0) {
                            # Find process that accessed the file
                            $accessingProcesses = @()
                            try {
                                $processes = Get-Process -ErrorAction SilentlyContinue
                                
                                foreach ($proc in $processes) {
                                    try {
                                        $procObj = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                                        
                                        if ($procObj.CommandLine -like "*$([System.IO.Path]::GetFileName($honeypotPath))*") {
                                            $accessingProcesses += $proc.ProcessName
                                        }
                                    } catch { }
                                }
                            } catch { }
                            
                            $detections += @{
                                HoneypotPath = $honeypotPath
                                LastAccess = $lastAccess
                                AccessCount = $honeypot.AccessCount
                                AccessingProcesses = $accessingProcesses -join ','
                                Type = "Honeypot File Accessed"
                                Risk = "Critical"
                            }
                            
                            # Log honeypot trigger
                            Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2041 `
                                -Message "HONEYPOT TRIGGERED: $honeypotPath was accessed - Processes: $($accessingProcesses -join ', ')"
                        }
                        
                        $honeypot.LastAccessed = $lastAccess
                    }
                } catch {
                    # File may have been deleted or moved
                    if (-not $honeypot.LastAccessed -or ((Get-Date) - $honeypot.Created).TotalMinutes -lt 5) {
                        $detections += @{
                            HoneypotPath = $honeypotPath
                            Type = "Honeypot File Deleted/Moved"
                            Risk = "Critical"
                        }
                        
                        Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2041 `
                            -Message "HONEYPOT DELETED: $honeypotPath was deleted or moved"
                        
                        # Recreate honeypot
                        Initialize-Honeypots
                    }
                }
            } else {
                # File doesn't exist - recreate
                Initialize-Honeypots
            }
        }
        
        # Check for processes accessing multiple honeypots (malware scanning)
        if ($detections.Count -gt 2) {
            $detections += @{
                HoneypotCount = $detections.Count
                Type = "Multiple Honeypots Accessed (Systematic Scanning)"
                Risk = "Critical"
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\Honeypot_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.HoneypotPath)|$($_.AccessingProcesses)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) honeypot access events"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    Initialize-Honeypots
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-HoneypotMonitoring
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
    Start-Module -Config @{ TickInterval = 300 }
}
