# Webcam Guardian Module
# Monitors webcam access and protects privacy

param([hashtable]$ModuleConfig)

$ModuleName = "WebcamGuardian"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 20 }

function Invoke-WebcamGuardian {
    $detections = @()
    
    try {
        # Check for webcam devices
        try {
            $webcamDevices = @(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Name -match 'camera|webcam|video|imaging|usb.*video' -or
                    $_.PNPDeviceID -match 'VID_.*PID_.*.*CAMERA'
                })
            
            if ($webcamDevices.Count -gt 0) {
                Write-Output "STATS:$ModuleName`:Webcam devices=$($webcamDevices.Count)"
            }
        } catch { }
        
        # Check for processes accessing webcam
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    # Check for webcam-related modules
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'ksuser|avicap32|msvfw32|amstream|qcap|vidcap'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Check if process is authorized
                        $authorizedProcesses = @("explorer.exe", "dwm.exe", "chrome.exe", "firefox.exe", "msedge.exe", "teams.exe", "zoom.exe", "skype.exe")
                        
                        if ($proc.ProcessName -notin $authorizedProcesses) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                ProcessPath = $proc.Path
                                WebcamModules = $modules.ModuleName -join ','
                                Type = "Unauthorized Webcam Access"
                                Risk = "High"
                            }
                        }
                    }
                    
                    # Check for video capture libraries
                    $videoModules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'video|capture|stream|directshow|media'
                    }
                    
                    if ($videoModules.Count -gt 3 -and 
                        $proc.ProcessName -notin $authorizedProcesses) {
                        $detections += @{
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            VideoModules = $videoModules.ModuleName -join ','
                            Type = "Process with Many Video Capture Modules"
                            Risk = "Medium"
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for webcam-related registry keys
        try {
            $webcamRegKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
            )
            
            foreach ($regKey in $webcamRegKeys) {
                if (Test-Path $regKey) {
                    $values = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
                    
                    if ($values) {
                        # Check for applications with webcam access
                        $appAccess = $values.PSObject.Properties | Where-Object {
                            $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') -and
                            $_.Value -ne "Deny"
                        }
                        
                        foreach ($app in $appAccess) {
                            # Check if app is suspicious
                            if ($app.Name -notmatch 'microsoft|windows|explorer|chrome|firefox|edge|teams|zoom|skype') {
                                $detections += @{
                                    RegistryKey = $regKey
                                    AppName = $app.Name
                                    Access = $app.Value
                                    Type = "Suspicious App with Webcam Access"
                                    Risk = "High"
                                }
                            }
                        }
                    }
                }
            }
        } catch { }
        
        # Check Event Log for webcam access
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='Application'} -ErrorAction SilentlyContinue -MaxEvents 500 |
                Where-Object { 
                    $_.Message -match 'camera|webcam|video.*capture|imaging.*device'
                }
            
            $webcamEvents = $events | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5)
            }
            
            if ($webcamEvents.Count -gt 10) {
                $detections += @{
                    EventCount = $webcamEvents.Count
                    Type = "Excessive Webcam Access Activity"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for webcam blocking/monitoring tools
        try {
            $processes = Get-CimInstance Win32_Process | 
                Where-Object { 
                    $_.Name -match 'camtasia|obs|webcam|camera|guardian|privacy'
                }
            
            foreach ($proc in $processes) {
                # These are usually legitimate, but log them
                Write-Output "STATS:$ModuleName`:Webcam-related process=$($proc.Name)"
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2031 `
                    -Message "WEBCAM GUARDIAN: $($detection.Type) - $($detection.ProcessName -or $detection.AppName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\WebcamGuardian_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.AppName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) webcam access anomalies"
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
                $count = Invoke-WebcamGuardian
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
    Start-Module -Config @{ TickInterval = 20 }
}
