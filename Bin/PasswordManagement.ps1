# Password Management Module
# Monitors password policies and storage

param([hashtable]$ModuleConfig)

$ModuleName = "PasswordManagement"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 300 }

function Invoke-PasswordManagement {
    $detections = @()
    
    try {
        # Check password policy
        try {
            $passwordPolicy = Get-LocalUser | ForEach-Object {
                $_.PasswordNeverExpires
            }
            
            $expiredPasswords = $passwordPolicy | Where-Object { $_ -eq $true }
            
            if ($expiredPasswords.Count -gt 0) {
                $detections += @{
                    ExpiredPasswordCount = $expiredPasswords.Count
                    Type = "Accounts with Non-Expiring Passwords"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for weak passwords (indirectly through failed logon attempts)
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue -MaxEvents 100
            
            $failedLogons = $securityEvents | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromHours(24)
            }
            
            if ($failedLogons.Count -gt 50) {
                $detections += @{
                    FailedLogonCount = $failedLogons.Count
                    Type = "Excessive Failed Logon Attempts - Possible Weak Passwords"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for password storage in plain text
        try {
            $searchPaths = @(
                "$env:USERPROFILE\Desktop",
                "$env:USERPROFILE\Documents",
                "$env:USERPROFILE\Downloads",
                "$env:TEMP"
            )
            
            $passwordFiles = @()
            foreach ($path in $searchPaths) {
                if (Test-Path $path) {
                    try {
                        $files = Get-ChildItem -Path $path -Filter "*.txt","*.log","*.csv" -File -ErrorAction SilentlyContinue |
                            Select-Object -First 50
                        
                        foreach ($file in $files) {
                            try {
                                $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                                if ($content -match '(?i)(password|pwd|passwd)\s*[:=]\s*\S+') {
                                    $passwordFiles += @{
                                        File = $file.FullName
                                        Type = "Plain Text Password Storage"
                                        Risk = "High"
                                    }
                                }
                            } catch { }
                        }
                    } catch { }
                }
            }
            
            $detections += $passwordFiles
        } catch { }
        
        # Check for credential dumping tools
        try {
            $credDumpTools = @("mimikatz", "lsadump", "pwdump", "fgdump", "hashdump")
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                foreach ($tool in $credDumpTools) {
                    if ($proc.ProcessName -like "*$tool*" -or 
                        $proc.Path -like "*$tool*") {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            Tool = $tool
                            Type = "Credential Dumping Tool"
                            Risk = "Critical"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for SAM database access
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656,4663} -ErrorAction SilentlyContinue -MaxEvents 500 |
                Where-Object { $_.Message -match 'SAM|SECURITY|SYSTEM' -and $_.Message -match 'Read|Write' }
            
            if ($securityEvents.Count -gt 0) {
                foreach ($event in $securityEvents) {
                    $detections += @{
                        EventId = $event.Id
                        TimeCreated = $event.TimeCreated
                        Message = $event.Message
                        Type = "SAM Database Access Attempt"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for LSA secrets access
        try {
            $lsaEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object { $_.Message -match 'LSA|Local.*Security.*Authority' }
            
            if ($lsaEvents.Count -gt 5) {
                $detections += @{
                    EventCount = $lsaEvents.Count
                    Type = "Excessive LSA Access Attempts"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2030 `
                    -Message "PASSWORD MANAGEMENT: $($detection.Type) - $($detection.ProcessName -or $detection.File -or $detection.Tool)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\PasswordManagement_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.File)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) password management issues"
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
                $count = Invoke-PasswordManagement
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
