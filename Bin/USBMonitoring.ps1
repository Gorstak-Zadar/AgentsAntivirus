# USB Device Monitoring Module
# Monitors USB device connections and activity

param([hashtable]$ModuleConfig)

$ModuleName = "USBMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

function Invoke-USBMonitoring {
    $detections = @()
    
    try {
        # Get USB devices (force array to avoid null reference on .Count)
        $usbDevices = @(Get-CimInstance Win32_USBControllerDevice -ErrorAction SilentlyContinue)
        
        foreach ($usbDevice in $usbDevices) {
            try {
                $device = Get-CimInstance -InputObject $usbDevice.Dependent -ErrorAction SilentlyContinue
                
                if ($device) {
                    # Check for suspicious USB device types
                    $suspiciousDevices = @{
                        "HID" = "Human Interface Device"
                        "USBSTOR" = "USB Mass Storage"
                    }
                    
                    $deviceType = $device.DeviceID
                    
                    # Check for HID devices (keyloggers, etc.)
                    if ($deviceType -match "HID") {
                        $detections += @{
                            DeviceId = $device.DeviceID
                            DeviceName = $device.Name
                            DeviceType = "HID Device"
                            Type = "USB HID Device Connected"
                            Risk = "Medium"
                        }
                    }
                    
                    # Check for USB storage devices
                    if ($deviceType -match "USBSTOR") {
                        $detections += @{
                            DeviceId = $device.DeviceID
                            DeviceName = $device.Name
                            DeviceType = "USB Storage"
                            Type = "USB Storage Device Connected"
                            Risk = "Low"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check Event Log for USB device events
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=20001,20002,20003} -ErrorAction SilentlyContinue -MaxEvents 100 |
                Where-Object { $_.Message -match 'USB|removable|storage' }
            
            $recentEvents = $events | Where-Object {
                (Get-Date) - $_.TimeCreated -lt [TimeSpan]::FromMinutes(5)
            }
            
            if ($recentEvents.Count -gt 5) {
                $detections += @{
                    EventCount = $recentEvents.Count
                    Type = "Excessive USB Device Activity"
                    Risk = "Medium"
                }
            }
        } catch { }
        
        # Check for USB device autorun
        try {
            $autorunKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            )
            
            foreach ($key in $autorunKeys) {
                if (Test-Path $key) {
                    $noDriveAutorun = Get-ItemProperty -Path $key -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
                    
                    if ($noDriveAutorun -and $noDriveAutorun.NoDriveTypeAutoRun -eq 0) {
                        $detections += @{
                            RegistryKey = $key
                            Type = "USB Autorun Enabled"
                            Risk = "High"
                        }
                    }
                }
            }
        } catch { }
        
        # Check for processes accessing USB devices
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue
            
            foreach ($proc in $processes) {
                try {
                    $modules = $proc.Modules | Where-Object {
                        $_.ModuleName -match 'usb|hid|storage'
                    }
                    
                    if ($modules.Count -gt 0) {
                        # Exclude legitimate processes
                        $legitProcesses = @("explorer.exe", "svchost.exe", "services.exe")
                        if ($proc.ProcessName -notin $legitProcesses) {
                            $detections += @{
                                ProcessId = $proc.Id
                                ProcessName = $proc.ProcessName
                                USBModules = $modules.ModuleName -join ','
                                Type = "Process Accessing USB Devices"
                                Risk = "Medium"
                            }
                        }
                    }
                } catch {
                    continue
                }
            }
        } catch { }
        
        # Check for USB device driver modifications
        try {
            $usbDrivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.PathName -match 'usb|hid' -and
                    $_.PathName -notlike "$env:SystemRoot\*"
                }
            
            foreach ($driver in $usbDrivers) {
                $detections += @{
                    DriverName = $driver.Name
                    DriverPath = $driver.PathName
                    Type = "Non-Standard USB Driver"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Information -EventId 2022 `
                    -Message "USB MONITORING: $($detection.Type) - $($detection.DeviceName -or $detection.ProcessName -or $detection.DriverName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\USBMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.DeviceName -or $_.ProcessName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) USB device anomalies"
        }
        
        Write-Output "STATS:$ModuleName`:USB devices=$($usbDevices.Count)"
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
                $count = Invoke-USBMonitoring
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
