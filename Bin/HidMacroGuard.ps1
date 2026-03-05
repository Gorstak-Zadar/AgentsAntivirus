# HID Macro Guard - Detects malicious HID/macro devices and suspicious driver/config
# USB HID keyboards/mice with macro firmware or button-injected payloads

param([hashtable]$ModuleConfig)

$ModuleName = "HidMacroGuard"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-HidMacroGuard {
    $detections = @()
    try {
        # Enumerate HID devices and drivers
        try {
            $hidDevices = Get-PnpDevice -Class HIDClass -ErrorAction SilentlyContinue
            foreach ($dev in $hidDevices) {
                if ($dev.Status -ne 'OK') { continue }
                $driver = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'DriverDesc' -ErrorAction SilentlyContinue
                $hardwareId = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName 'HardwareID' -ErrorAction SilentlyContinue).Data
                if (-not $hardwareId) { $hardwareId = @() } else { $hardwareId = @($hardwareId) }
                $desc = ($driver.Data -join ' ') -replace '\s+', ' '
                # Known macro/Rubber Ducky style hardware IDs or driver names
                if ($desc -match 'HID.*Boot|Keyboard|Mouse' -and $desc -match 'composite|multi|macro') {
                    $detections += @{
                        Type = "HID composite/macro device"
                        Description = $desc
                        InstanceId = $dev.InstanceId
                        Risk = "Medium"
                    }
                }
                foreach ($hid in $hardwareId) {
                    if ($hid -match 'vid_([0-9a-f]{4})&pid_([0-9a-f]{4})') {
                        # Optional: check against known bad VID/PID list (example placeholders)
                        $vid = $Matches[1]; $pid = $Matches[2]
                        # e.g. Rubber Ducky and similar have been seen with certain VID/PIDs - add blocklist if desired
                    }
                }
            }
        } catch { }

        # Registry: HID-related persistence or filter drivers
        $hidRegPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\*\Parameters",
            "HKLM:\SYSTEM\CurrentControlSet\Enum\HID"
        )
        try {
            $suspiciousHid = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^Hid|kbdclass|mouclass' }
            foreach ($svc in $suspiciousHid) {
                $imgPath = Get-ItemProperty -Path $svc.PSPath -Name "ImagePath" -ErrorAction SilentlyContinue
                if ($imgPath -and $imgPath.ImagePath -notmatch '\\System32\\drivers\\') {
                    $detections += @{
                        Type = "Non-default HID/keyboard/mouse driver path"
                        Service = $svc.PSChildName
                        ImagePath = $imgPath.ImagePath
                        Risk = "High"
                    }
                }
            }
        } catch { }

        # Filter drivers (upper/lower filter) that could inject keystrokes
        try {
            $kbd = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass" -ErrorAction SilentlyContinue
            $mou = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass" -ErrorAction SilentlyContinue
            foreach ($node in @($kbd, $mou)) {
                if (-not $node) { continue }
                $upper = $node.UpperFilters -join ','
                $lower = $node.LowerFilters -join ','
                $all = "$upper $lower"
                if ($all -match '[\w\.]+\.(sys|dll)' -and $all -notmatch 'kbdclass|mouclass|i8042prt|kbdhid|mouhid') {
                    $detections += @{
                        Type = "Unexpected keyboard/mouse filter driver"
                        Filters = $all
                        Risk = "Medium"
                    }
                }
            }
        } catch { }

        # Processes that might be HID/macro injectors (named pipes or raw input)
        try {
            $procs = Get-CimInstance Win32_Process | Where-Object {
                $_.Name -match 'hid|macro|keyboard|inject|ducky'
            }
            foreach ($p in $procs) {
                $path = $p.ExecutablePath
                if (-not $path -or -not (Test-Path $path)) { continue }
                $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                if ($sig.Status -ne 'Valid') {
                    $detections += @{
                        Type = "Unsigned HID/macro-related process"
                        ProcessId = $p.ProcessId
                        ProcessName = $p.Name
                        Path = $path
                        Risk = "High"
                    }
                }
            }
        } catch { }

        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                $msg = "HidMacroGuard: $($d.Type) - $($d.Description -or $d.Service -or $d.ProcessName -or $d.Filters)"
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2093 -Message $msg -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\HidMacroGuard_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.Description -or $_.Service -or $_.ProcessName)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) HID/macro issues"
        } else {
            Write-Output "STATS:$ModuleName`:OK"
        }
        return $detections.Count
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
        return 0
    }
}

function Start-Module {
    param([hashtable]$Config)
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                Invoke-HidMacroGuard | Out-Null
                $LastTick = $now
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Output "ERROR:$ModuleName`:$_"
            Start-Sleep -Seconds 10
        }
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{} }
