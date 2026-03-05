# Quarantine Management Module
# Manages file quarantine operations and tracks quarantined files

param([hashtable]$ModuleConfig)

$ModuleName = "QuarantineManagement"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 300 }
$QuarantinePath = "$env:ProgramData\Antivirus\Quarantine"

function Initialize-Quarantine {
    try {
        if (-not (Test-Path $QuarantinePath)) {
            New-Item -Path $QuarantinePath -ItemType Directory -Force | Out-Null
        }
        
        # Create quarantine log
        $quarantineLog = Join-Path $QuarantinePath "quarantine_log.txt"
        if (-not (Test-Path $quarantineLog)) {
            "Timestamp|FilePath|QuarantinePath|Reason|FileHash" | Add-Content -Path $quarantineLog
        }
        
        return $true
    } catch {
        Write-Output "ERROR:$ModuleName`:Failed to initialize quarantine: $_"
        return $false
    }
}

function Invoke-QuarantineFile {
    param(
        [string]$FilePath,
        [string]$Reason = "Threat Detected",
        [string]$Source = "Unknown"
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-Output "ERROR:$ModuleName`:File not found: $FilePath"
            return $false
        }
        
        $fileName = Split-Path -Leaf $FilePath
        $fileDir = Split-Path -Parent $FilePath
        $fileBaseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        $fileExt = [System.IO.Path]::GetExtension($fileName)
        
        # Generate unique quarantine filename with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $quarantineFileName = "${fileBaseName}_${timestamp}${fileExt}"
        $quarantineFilePath = Join-Path $QuarantinePath $quarantineFileName
        
        # Calculate file hash before moving
        $fileHash = $null
        try {
            $hashObj = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            $fileHash = $hashObj.Hash
        } catch { }
        
        # Move file to quarantine
        Move-Item -Path $FilePath -Destination $quarantineFilePath -Force -ErrorAction Stop
        
        # Log quarantine action
        $quarantineLog = Join-Path $QuarantinePath "quarantine_log.txt"
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$FilePath|$quarantineFilePath|$Reason|$fileHash"
        Add-Content -Path $quarantineLog -Value $logEntry
        
        # Write Event Log
        Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2034 `
            -Message "QUARANTINE: File quarantined: $fileName - Reason: $Reason - Source: $Source"
        
        Write-Output "STATS:$ModuleName`:File quarantined: $fileName"
        return $true
    } catch {
        Write-Output "ERROR:$ModuleName`:Failed to quarantine $FilePath`: $_"
        return $false
    }
}

function Invoke-QuarantineManagement {
    $stats = @{
        QuarantinedFiles = 0
        QuarantineSize = 0
        OldFiles = 0
    }
    
    try {
        # Initialize quarantine if needed
        if (-not (Test-Path $QuarantinePath)) {
            Initialize-Quarantine
        }
        
        # Check quarantine status
        if (Test-Path $QuarantinePath) {
            $quarantinedFiles = Get-ChildItem -Path $QuarantinePath -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne "quarantine_log.txt" }
            
            $stats.QuarantinedFiles = $quarantinedFiles.Count
            
            # Calculate total quarantine size
            foreach ($file in $quarantinedFiles) {
                $stats.QuarantineSize += $file.Length
            }
            
            # Check for old quarantined files (older than 90 days)
            $cutoffDate = (Get-Date).AddDays(-90)
            $oldFiles = $quarantinedFiles | Where-Object { $_.LastWriteTime -lt $cutoffDate }
            $stats.OldFiles = $oldFiles.Count
            
            # Optionally remove old files
            if ($stats.OldFiles -gt 0 -and $stats.QuarantineSize -gt 1GB) {
                foreach ($oldFile in $oldFiles) {
                    try {
                        Remove-Item -Path $oldFile.FullName -Force -ErrorAction SilentlyContinue
                        Write-Output "STATS:$ModuleName`:Removed old quarantined file: $($oldFile.Name)"
                    } catch { }
                }
            }
        }
        
        # Check quarantine log integrity
        $quarantineLog = Join-Path $QuarantinePath "quarantine_log.txt"
        if (Test-Path $quarantineLog) {
            $logEntries = Get-Content -Path $quarantineLog -ErrorAction SilentlyContinue
            if ($logEntries.Count -gt 10000) {
                # Archive old log entries
                $archivePath = Join-Path $QuarantinePath "quarantine_log_$(Get-Date -Format 'yyyy-MM-dd').txt"
                Copy-Item -Path $quarantineLog -Destination $archivePath -ErrorAction SilentlyContinue
                "Timestamp|FilePath|QuarantinePath|Reason|FileHash" | Set-Content -Path $quarantineLog
            }
        }
        
        Write-Output "STATS:$ModuleName`:Quarantined=$($stats.QuarantinedFiles), Size=$([Math]::Round($stats.QuarantineSize/1MB, 2))MB, Old=$($stats.OldFiles)"
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $stats
}

function Start-Module {
    param([hashtable]$Config)
    
    Initialize-Quarantine
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $stats = Invoke-QuarantineManagement
                $LastTick = $now
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

# Export quarantine function for use by other modules
if ($ModuleConfig) {
    $ModuleConfig.QuarantineFunction = ${function:Invoke-QuarantineFile}
}

if (-not $ModuleConfig) {
    Start-Module -Config @{ TickInterval = 300 }
}
