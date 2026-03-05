# BCD Security - Boot Configuration Data protection and integrity checks
# Detects tampered boot config, disabled secure boot, test signing, hypervisor abuse

param([hashtable]$ModuleConfig)

$ModuleName = "BCDSecurity"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 300 }

function Invoke-BCDSecurity {
    $detections = @()
    try {
        # Export current BCD and check for dangerous flags
        $bcdOut = bcdedit /enum 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { return 0 }

        # Test signing / no integrity checks (often used by bootkits)
        if ($bcdOut -match 'testsigning\s+Yes') {
            $detections += @{ Type = "Test signing enabled"; Risk = "High"; Detail = "testsigning Yes" }
        }
        if ($bcdOut -match 'nointegritychecks\s+Yes') {
            $detections += @{ Type = "No integrity checks"; Risk = "Critical"; Detail = "nointegritychecks Yes" }
        }
        if ($bcdOut -match 'nx\s+OptOut') {
            $detections += @{ Type = "DEP disabled (nx OptOut)"; Risk = "High"; Detail = "nx OptOut" }
        }

        # Boot menu policy legacy can bypass secure boot
        if ($bcdOut -match 'bootmenupolicy\s+Legacy') {
            $detections += @{ Type = "Legacy boot menu policy"; Risk = "Medium"; Detail = "bootmenupolicy Legacy" }
        }

        # Hypervisor launch options (could hide rootkits)
        if ($bcdOut -match 'hypervisorlaunchtype\s+Off' -and $bcdOut -match 'hypervisorlaunchtype') {
            # Only flag if explicitly set Off in a hypervisor-related entry and we expect it on in a secure config
        }
        if ($bcdOut -match 'hypervisorlaunchtype\s+Auto' -and $bcdOut -match 'debug\s+Yes') {
            $detections += @{ Type = "Hypervisor debug enabled"; Risk = "Medium"; Detail = "hypervisor debug Yes" }
        }

        # Unknown or non-default boot loaders
        $loaderPaths = [regex]::Matches($bcdOut, 'path\s+(\S+)') | ForEach-Object { $_.Groups[1].Value.Trim() }
        $sysRoot = $env:SystemRoot
        foreach ($path in $loaderPaths) {
            $p = $path -replace '\\Device\\HarddiskVolume\d+', $env:SystemDrive
            if ($p -match '\\Windows\\System32\\winload\.(exe|efi)' -or $p -match '\\EFI\\Microsoft\\Boot\\bootmgfw\.efi') { continue }
            if ($p -match '\.(exe|efi)$' -and $p -notlike "*$sysRoot*" -and $p -notlike '*\EFI\*') {
                $detections += @{ Type = "Non-default boot loader"; Risk = "High"; Detail = $path }
            }
        }

        # Secure Boot status (via WMI / firmware)
        try {
            $secureBoot = Get-CimInstance -Namespace root\Microsoft\Windows\SecureBoot -ClassName UEFI_SecureBoot -ErrorAction SilentlyContinue
            if ($secureBoot -and $secureBoot.SecureBootEnabled -eq $false) {
                $detections += @{ Type = "Secure Boot disabled"; Risk = "High"; Detail = "UEFI SecureBoot disabled" }
            }
        } catch { }

        # BCD store location tampering (default is \boot\bcd)
        try {
            $bcdPath = Join-Path $env:SystemRoot "boot\bcd"
            if (Test-Path $bcdPath) {
                $acl = Get-Acl -Path $bcdPath -ErrorAction SilentlyContinue
                $everyone = $acl.Access | Where-Object { $_.IdentityReference -match 'Everyone|Users' -and $_.FileSystemRights -match 'Write|Modify' }
                if ($everyone) {
                    $detections += @{ Type = "BCD store writable by broad identity"; Risk = "Medium"; Detail = $bcdPath }
                }
            }
        } catch { }

        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2091 `
                    -Message "BCDSecurity: $($d.Type) - $($d.Detail)" -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\BCDSecurity_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.Detail)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) BCD issues"
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
                Invoke-BCDSecurity | Out-Null
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
