# Ransomware Detection Module
# Detects ransomware encryption patterns

param([hashtable]$ModuleConfig)

$ModuleName = "RansomwareDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 15 }

function Invoke-RansomwareScan {
    $detections = @()
    
    try {
        # Check for rapid file modifications (encryption indicator)
        $userDirs = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Pictures",
            "$env:USERPROFILE\Videos"
        )
        
        $recentFiles = @()
        foreach ($dir in $userDirs) {
            if (Test-Path $dir) {
                try {
                    $files = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { (Get-Date) - $_.LastWriteTime -lt [TimeSpan]::FromMinutes(5) } |
                        Select-Object -First 100
                    
                    $recentFiles += $files
                } catch { }
            }
        }
        
        # Check for files with suspicious extensions
        $suspiciousExts = @(".encrypted", ".locked", ".crypto", ".vault", ".xxx", ".zzz", ".xyz")
        $encryptedFiles = $recentFiles | Where-Object {
            $ext = $_.Extension.ToLower()
            $ext -in $suspiciousExts -or
            ($ext -notin @(".txt", ".doc", ".pdf", ".jpg", ".png") -and $ext.Length -gt 4)
        }
        
        if ($encryptedFiles.Count -gt 10) {
            $detections += @{
                Type = "Rapid File Encryption"
                EncryptedFiles = $encryptedFiles.Count
                Risk = "Critical"
            }
        }
        
        # Check for ransom notes
        $ransomNoteNames = @("readme.txt", "decrypt.txt", "how_to_decrypt.txt", "recover.txt", "restore.txt", "!!!readme!!!.txt")
        foreach ($file in $recentFiles) {
            if ($file.Name -in $ransomNoteNames) {
                $detections += @{
                    File = $file.FullName
                    Type = "Ransom Note Detected"
                    Risk = "Critical"
                }
            }
        }
        
        # Check for processes with high file I/O
        try {
            $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
            
            foreach ($proc in $processes) {
                try {
                    $procObj = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                    
                    # Check for processes with unusual file activity
                    $ioStats = Get-Counter "\Process($($proc.Name))\IO Data Operations/sec" -ErrorAction SilentlyContinue
                    if ($ioStats -and $ioStats.CounterSamples[0].CookedValue -gt 1000) {
                        # High I/O activity
                        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) {
                            $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    ProcessId = $proc.ProcessId
                                    ProcessName = $proc.Name
                                    IOOperations = $ioStats.CounterSamples[0].CookedValue
                                    Type = "High File I/O - Unsigned Process"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for shadow copy deletion
        try {
            $shadowCopies = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
            if ($shadowCopies.Count -eq 0 -and (Test-Path "C:\Windows\System32\vssadmin.exe")) {
                $detections += @{
                    Type = "Shadow Copies Deleted"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for crypto API usage
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            foreach ($proc in $processes) {
                $modules = $proc.Modules | Where-Object {
                    $_.ModuleName -match "crypt32|cryptsp|cryptnet|bcrypt"
                }
                
                if ($modules.Count -gt 0) {
                    # Check if process is accessing many files
                    try {
                        $handles = Get-CimInstance Win32_ProcessHandle -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                        $fileHandles = $handles | Where-Object { $_.Name -like "*.txt" -or $_.Name -like "*.doc*" -or $_.Name -like "*.pdf" }
                        
                        if ($fileHandles.Count -gt 50) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                FileHandles = $fileHandles.Count
                                Type = "Cryptographic API with High File Access"
                                Risk = "High"
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Error -EventId 2014 `
                    -Message "RANSOMWARE DETECTED: $($detection.Type) - $($detection.ProcessName -or $detection.File -or $detection.EncryptedFiles)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\Ransomware_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.File -or $_.EncryptedFiles)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) ransomware indicators"
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
                $count = Invoke-RansomwareScan
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
    Start-Module -Config @{ TickInterval = 15 }
}
