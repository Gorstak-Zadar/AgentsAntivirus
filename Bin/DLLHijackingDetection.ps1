# DLL Hijacking Detection Agent
# Standalone agent for AV - detects DLL hijacking and UAC bypass vectors
# Matches DLLHijackHunter-style discovery:
#   - COM AutoElevation: HKLM\SOFTWARE\Classes\CLSID (InprocServer32/LocalServer32)
#   - Manifest AutoElevate: System32/SysWOW64 binaries with <autoElevate>true</autoElevate>
#   - Copy & Drop: AutoElevate binaries lacking SetDllDirectory/SetDefaultDllDirectories
#
# Usage:
#   .\DLLHijackingDetection.ps1                    # Full scan (default)
#   .\DLLHijackingDetection.ps1 --profile uac-bypass   # UAC bypass vectors only
#   .\DLLHijackingDetection.ps1 --profile standard    # Standard DLL hijack detection only

param(
    [hashtable]$ModuleConfig,
    [string]$Profile = "full"  # full | uac-bypass | standard
)

$ModuleName = "DLLHijackingDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

# Use profile from config if specified
if ($ModuleConfig.Profile) { $Profile = $ModuleConfig.Profile }

#region UAC Bypass Module (DLLHijackHunter-style)

function Get-COMAutoElevationVectors {
    # Scans HKLM\SOFTWARE\Classes\CLSID for COM objects with Elevation\Enabled=1
    # Finds bypass vectors akin to Fodhelper, CMSTPLUA
    $detections = @()
    $clsidPaths = @(
        "HKLM:\SOFTWARE\Classes\CLSID\*",
        "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\*"
    )
    
    foreach ($path in $clsidPaths) {
        try {
            $clsidKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
            foreach ($key in $clsidKeys) {
                try {
                    $elevationPath = "$($key.PSPath)\Elevation"
                    $elevationKey = Get-ItemProperty -Path $elevationPath -ErrorAction SilentlyContinue
                    if ($elevationKey -and $elevationKey.Enabled -eq 1) {
                        $targetPath = $null
                        $targetType = $null
                        
                        # Check InprocServer32 (DLL)
                        $inprocPath = "$($key.PSPath)\InprocServer32"
                        if (Test-Path $inprocPath) {
                            $inproc = Get-ItemProperty -Path $inprocPath -ErrorAction SilentlyContinue
                            if ($inproc -and $inproc.(default)) {
                                $targetPath = $inproc.(default)
                                $targetType = "InprocServer32 (DLL)"
                            }
                        }
                        
                        # Check LocalServer32 (EXE)
                        if (-not $targetPath) {
                            $localPath = "$($key.PSPath)\LocalServer32"
                            if (Test-Path $localPath) {
                                $local = Get-ItemProperty -Path $localPath -ErrorAction SilentlyContinue
                                if ($local -and $local.(default)) {
                                    $targetPath = $local.(default)
                                    $targetType = "LocalServer32 (EXE)"
                                }
                            }
                        }
                        
                        if ($targetPath) {
                            # Expand environment variables in path
                            $targetPath = $targetPath -replace '%SystemRoot%', $env:SystemRoot
                            $targetPath = $targetPath -replace '%ProgramFiles%', $env:ProgramFiles
                            $targetPath = $targetPath -replace '^"|"$', ''
                            $targetPath = ($targetPath -split '\s+')[0]
                            
                            $detections += @{
                                Vector = "COM AutoElevation"
                                CLSID = Split-Path $key.PSPath -Leaf
                                TargetPath = $targetPath
                                TargetType = $targetType
                                PrivilegeLevel = "High"  # COM Elevation = High Integrity
                                Risk = "High"
                                RegistryPath = $key.PSPath
                            }
                        }
                    }
                } catch { continue }
            }
        } catch { }
    }
    
    return $detections
}

function Get-ManifestAutoElevateBinaries {
    # Scans System32 and SysWOW64 for binaries with <autoElevate>true</autoElevate>
    $detections = @()
    $searchPaths = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64"
    )
    
    $binaries = @()
    foreach ($path in $searchPaths) {
        if (-not (Test-Path $path)) { continue }
        $binaries += Get-ChildItem -Path $path -Include "*.exe" -File -ErrorAction SilentlyContinue | Select-Object -First 500
    }
    
    foreach ($bin in $binaries) {
        try {
            # Check embedded manifest (resources) or external .manifest file
            $manifestPath = "$($bin.FullName).manifest"
            $content = $null
            
            if (Test-Path $manifestPath) {
                $content = Get-Content -Path $manifestPath -Raw -ErrorAction SilentlyContinue
            } else {
                # Embedded manifest in PE - search ASCII and Unicode
                $bytes = [System.IO.File]::ReadAllBytes($bin.FullName)
                $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
                $unicode = [System.Text.Encoding]::Unicode.GetString($bytes)
                if ($ascii -match 'autoElevate[\s>]*true' -or $unicode -match 'autoElevate[\s>]*true') {
                    $content = "autoElevate present"
                }
            }
            
            if ($content -and ($content -match 'autoElevate[\s>]*true|autoElevate\s*>\s*true')) {
                $vulnerableToCopyDrop = Test-CopyDropVulnerable -BinaryPath $bin.FullName
                
                $detections += @{
                    Vector = "Manifest AutoElevate"
                    BinaryPath = $bin.FullName
                    BinaryName = $bin.Name
                    VulnerableToCopyDrop = $vulnerableToCopyDrop
                    PrivilegeLevel = "High"
                    Risk = if ($vulnerableToCopyDrop) { "Critical" } else { "High" }
                }
            }
        } catch { continue }
    }
    
    return $detections
}

function Test-CopyDropVulnerable {
    # Checks if binary does NOT import SetDllDirectory or SetDefaultDllDirectories
    # Such binaries are vulnerable to copy-to-%TEMP% side-load simulation
    param([string]$BinaryPath)
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        
        # If either safe API is present, binary is protected
        $hasSetDllDirectory = $ascii -match 'SetDllDirectory'
        $hasSetDefaultDllDirectories = $ascii -match 'SetDefaultDllDirectories'
        
        return -not ($hasSetDllDirectory -or $hasSetDefaultDllDirectories)
    } catch {
        return $false  # Assume protected if we can't read
    }
}

function Invoke-UACBypassScan {
    $detections = @()
    $detections += Get-COMAutoElevationVectors
    $detections += Get-ManifestAutoElevateBinaries
    
    return $detections
}

#endregion

#region Standard Detection (existing logic)

function Test-DLLHijacking {
    param([string]$DllPath)
    
    if (-not (Test-Path $DllPath)) { return $false }
    
    $suspiciousPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:APPDATA",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    
    foreach ($susPath in $suspiciousPaths) {
        if ($DllPath -like "$susPath*") {
            return $true
        }
    }
    
    try {
        $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
        if ($sig.Status -ne "Valid") {
            return $true
        }
    } catch { }
    
    return $false
}

function Invoke-StandardDLLHijackScan {
    $detections = @()
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue
        
        foreach ($proc in $processes) {
            try {
                $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" }
                foreach ($module in $modules) {
                    if (Test-DLLHijacking -DllPath $module.FileName) {
                        $detections += @{
                            Vector = "Loaded DLL"
                            ProcessId = $proc.Id
                            ProcessName = $proc.ProcessName
                            DllPath = $module.FileName
                            DllName = $module.ModuleName
                            Risk = "High"
                        }
                    }
                }
            } catch { continue }
        }
        
        $appPaths = @(
            "$env:ProgramFiles",
            "$env:ProgramFiles(x86)",
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64"
        )
        
        foreach ($appPath in $appPaths) {
            if (-not (Test-Path $appPath)) { continue }
            try {
                $dlls = Get-ChildItem -Path $appPath -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 100
                foreach ($dll in $dlls) {
                    if ($dll.DirectoryName -ne $appPath) {
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $dll.FullName -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid") {
                                $detections += @{
                                    Vector = "Unsigned DLL in app dir"
                                    DllPath = $dll.FullName
                                    Type = "Unsigned DLL in application directory"
                                    Risk = "Medium"
                                }
                            }
                        } catch { }
                    }
                }
            } catch { }
        }
        
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $events) {
                if ($event.Message -match 'DLL.*not.*found|DLL.*load.*failed') {
                    $detections += @{
                        Vector = "DLL Load Failure"
                        EventId = $event.Id
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                        Type = "DLL Load Failure"
                        Risk = "Medium"
                    }
                }
            }
        } catch { }
    } catch { }
    
    return $detections
}

#endregion

#region Main Scan Dispatcher

function Invoke-DLLHijackingScan {
    $detections = @()
    
    switch ($Profile) {
        "uac-bypass" {
            $detections = Invoke-UACBypassScan
        }
        "standard" {
            $detections = Invoke-StandardDLLHijackScan
        }
        "full" {
            $detections = Invoke-UACBypassScan
            $detections += Invoke-StandardDLLHijackScan
        }
        default {
            $detections = Invoke-UACBypassScan
            $detections += Invoke-StandardDLLHijackScan
        }
    }
    
    try {
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                $msg = switch ($detection.Vector) {
                    "COM AutoElevation" { "UAC BYPASS (COM): $($detection.CLSID) -> $($detection.TargetPath) [$($detection.PrivilegeLevel)]" }
                    "Manifest AutoElevate" { "UAC BYPASS (Manifest): $($detection.BinaryPath)" + $(if ($detection.VulnerableToCopyDrop) { " [COPY-DROP VULN]" } else { "" }) }
                    default { "DLL HIJACKING: $($detection.ProcessName -or $detection.Type) - $($detection.DllPath -or $detection.Message)" }
                }
                try {
                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2009 -Message $msg -ErrorAction SilentlyContinue
                } catch { }
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\DLLHijacking_$(Get-Date -Format 'yyyy-MM-dd').log"
            $logDir = Split-Path $logPath -Parent
            if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
            
            $detections | ForEach-Object {
                $line = switch ($_.Vector) {
                    "COM AutoElevation" { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Vector)|$($_.CLSID)|$($_.TargetPath)|$($_.PrivilegeLevel)|$($_.Risk)" }
                    "Manifest AutoElevate" { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Vector)|$($_.BinaryPath)|CopyDrop=$($_.VulnerableToCopyDrop)|$($_.Risk)" }
                    default { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ProcessName -or $_.Type)|$($_.DllPath -or $_.DllName)|$($_.Risk)" }
                }
                Add-Content -Path $logPath -Value $line -ErrorAction SilentlyContinue
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) vectors (profile=$Profile)"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

#endregion

#region Agent Entry Point

function Start-Module {
    param([hashtable]$Config)
    
    $profileToUse = if ($Config.Profile) { $Config.Profile } else { $Profile }
    Write-Output "INIT:$ModuleName`:Started (profile=$profileToUse, interval=$TickInterval)"
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-DLLHijackingScan
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

# Run
if (-not $ModuleConfig) {
    # Parse profile from args: .\DLLHijackingDetection.ps1 -Profile uac-bypass
    $argsProfile = $args | Where-Object { $_ -match '^--profile[= ]?(.+)$' }
    if ($argsProfile) {
        $Profile = ($argsProfile -split '=',2)[-1].Trim()
    }
    Start-Module -Config @{ TickInterval = 60; Profile = $Profile }
} else {
    Start-Module -Config $ModuleConfig
}
