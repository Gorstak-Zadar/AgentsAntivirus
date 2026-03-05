# Shadow Copy Monitoring Module
# Monitors shadow copy deletion (ransomware indicator)

param([hashtable]$ModuleConfig)

$ModuleName = "ShadowCopyMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-ShadowCopyMonitoring {
    $detections = @()
    
    try {
        # Check for shadow copies (force array to avoid null reference)
        $shadowCopies = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
        
        # Check shadow copy count
        if ($shadowCopies.Count -eq 0) {
            $detections += @{
                Type = "No Shadow Copies Found"
                ShadowCopyCount = 0
                Risk = "Medium"
            }
        }
        
        # Monitor shadow copy deletion
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'} -ErrorAction SilentlyContinue -MaxEvents 200 |
                Where-Object { 
                    $_.Message -match 'shadow|vss|volume.*snapshot' -or
                    $_.Id -in @(8221, 8222, 8223, 8224)
                }
            
            $deletionEvents = $events | Where-Object {
                $_.Message -match 'delete|deleted|remove|removed'
            }
            
            if ($deletionEvents.Count -gt 0) {
                foreach ($event in $deletionEvents) {
                    $detections += @{
                        EventId = $event.Id
                        TimeCreated = $event.TimeCreated
                        Message = $event.Message
                        Type = "Shadow Copy Deletion Detected"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check for VSSAdmin usage
        try {
            $processes = Get-CimInstance Win32_Process | 
                Where-Object { $_.Name -eq "vssadmin.exe" -or $_.CommandLine -like "*vssadmin*" }
            
            foreach ($proc in $processes) {
                if ($proc.CommandLine -match 'delete.*shadows|resize.*shadowstorage') {
                    $detections += @{
                        ProcessId = $proc.ProcessId
                        ProcessName = $proc.Name
                        CommandLine = $proc.CommandLine
                        Type = "VSSAdmin Shadow Copy Manipulation"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        # Check for Volume Shadow Copy Service status
        try {
            $vssService = Get-CimInstance Win32_Service -Filter "Name='VSS'" -ErrorAction SilentlyContinue
            
            if ($vssService) {
                if ($vssService.State -ne "Running") {
                    $detections += @{
                        ServiceState = $vssService.State
                        Type = "Volume Shadow Copy Service Not Running"
                        Risk = "High"
                    }
                }
            }
        } catch { }
        
        # Check shadow storage configuration
        try {
            $shadowStorage = Get-CimInstance Win32_ShadowStorage -ErrorAction SilentlyContinue
            
            foreach ($storage in $shadowStorage) {
                # Check if shadow storage is disabled or too small
                $allocated = $storage.AllocatedSpace
                $maxSize = $storage.MaxSpace
                
                if ($maxSize -eq 0 -or $allocated -eq 0) {
                    $detections += @{
                        Volume = $storage.Volume
                        AllocatedSpace = $allocated
                        MaxSpace = $maxSize
                        Type = "Shadow Storage Disabled or Empty"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2021 `
                    -Message "SHADOW COPY MONITORING: $($detection.Type) - $($detection.ProcessName -or $detection.Volume -or $detection.Message)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\ShadowCopy_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.Volume)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) shadow copy anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:Shadow copies=$($shadowCopies.Count)"
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
                $count = Invoke-ShadowCopyMonitoring
                $LastTick = $now
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
