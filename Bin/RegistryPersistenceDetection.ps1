# Registry Persistence Detection Module
# Detects malicious registry-based persistence

param([hashtable]$ModuleConfig)

$ModuleName = "RegistryPersistenceDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

$PersistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

function Test-SuspiciousRegistryValue {
    param([string]$Value)
    
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    
    $valueLower = $Value.ToLower()
    
    # Check for suspicious patterns
    $suspiciousPatterns = @(
        'powershell.*-encodedcommand',
        'powershell.*-nop.*-w.*hidden',
        'cmd.*\/c.*powershell',
        'wscript.*http',
        'cscript.*http',
        'rundll32.*javascript',
        'mshta.*http',
        'certutil.*urlcache',
        'bitsadmin.*transfer',
        'regsvr32.*http',
        '\.exe.*http',
        '\.dll.*http'
    )
    
    foreach ($pattern in $suspiciousPatterns) {
        if ($valueLower -match $pattern) {
            return $true
        }
    }
    
    # Check for suspicious file locations
    if ($valueLower -match '\$env:' -and 
        ($valueLower -match 'temp|appdata|local' -or 
         $valueLower -notmatch '^[A-Z]:\\')) {
        return $true
    }
    
    # Check for unsigned executables
    if ($valueLower -like '*.exe' -or $valueLower -like '*.dll') {
        $filePath = $valueLower -replace '"', '' -split ' ' | Select-Object -First 1
        if ($filePath -and (Test-Path $filePath)) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
                if ($sig.Status -ne "Valid") {
                    return $true
                }
            } catch { }
        }
    }
    
    return $false
}

function Invoke-RegistryPersistenceScan {
    $detections = @()
    
    try {
        foreach ($regPath in $PersistenceKeys) {
            if (-not (Test-Path $regPath)) { continue }
            
            try {
                $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($values) {
                    $valueProps = $values.PSObject.Properties | Where-Object { 
                        $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
                    }
                    
                    foreach ($prop in $valueProps) {
                        $regValue = $prop.Value
                        $regName = $prop.Name
                        
                        if (Test-SuspiciousRegistryValue -Value $regValue) {
                            $detections += @{
                                RegistryPath = $regPath
                                ValueName = $regName
                                Value = $regValue
                                Risk = "High"
                            }
                        }
                    }
                }
            } catch { }
        }
        
        # Check for suspicious service entries
        try {
            $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.PathName -match 'powershell|cmd|wscript|cscript|http' -or
                    $_.StartName -eq 'LocalSystem' -and $_.PathName -notmatch '^[A-Z]:\\Windows'
                }
            
            foreach ($svc in $services) {
                if (Test-SuspiciousRegistryValue -Value $svc.PathName) {
                    $detections += @{
                        RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
                        ValueName = "ImagePath"
                        Value = $svc.PathName
                        ServiceName = $svc.Name
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2008 `
                    -Message "REGISTRY PERSISTENCE: $($detection.RegistryPath)\$($detection.ValueName) - $($detection.Value)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\RegistryPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.RegistryPath)|$($_.ValueName)|$($_.Value)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) registry persistence mechanisms"
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
                $count = Invoke-RegistryPersistenceScan
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
