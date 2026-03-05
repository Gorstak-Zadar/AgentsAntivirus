# Mobile Device Monitoring
# Win32_PnPEntity for portable/USB/MTP devices

param([hashtable]$ModuleConfig)

$ModuleName = "MobileDeviceMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 90 }

$DeviceClasses = @("USB", "Bluetooth", "Image", "WPD", "PortableDevice", "MTP")
$KnownDevices = @{}

function Invoke-MobileDeviceScan {
    $newDevices = @()
    try {
        $devices = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
            foreach ($cls in $DeviceClasses) {
                if (($_.PNPClass -eq $cls) -or ($_.Service -like "*$cls*")) {
                    return $true
                }
            }
            return $false
        }
        
        foreach ($d in $devices) {
            $key = $d.DeviceID
            if (-not $script:KnownDevices.ContainsKey($key)) {
                $script:KnownDevices[$key] = $true
                $newDevices += @{
                    DeviceID = $d.DeviceID
                    Name = $d.Name
                    PNPClass = $d.PNPClass
                    Status = $d.Status
                }
            }
        }
        
        if ($newDevices.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\mobile_device_$(Get-Date -Format 'yyyy-MM-dd').log"
            foreach ($nd in $newDevices) {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|New device|$($nd.Name)|$($nd.PNPClass)|$($nd.DeviceID)" | Add-Content -Path $logPath
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Information -EventId 2094 -Message "MOBILE DEVICE: $($nd.Name) - $($nd.PNPClass)" -ErrorAction SilentlyContinue
            }
            Write-Output "STATS:$ModuleName`:Logged $($newDevices.Count) new mobile/USB devices"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
}

function Start-Module {
    param([hashtable]$Config)
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $script:LastTick).TotalSeconds -ge $script:TickInterval) {
                $script:LastTick = $now
                Invoke-MobileDeviceScan
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{ TickInterval = 90 } }
