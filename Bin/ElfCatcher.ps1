# Elf Catcher Module
# Monitors browser processes for suspicious DLL injection (ELF pattern detection)

param([hashtable]$ModuleConfig)

$ModuleName = "ElfCatcher"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 30 }

# DLL whitelist - safe system DLLs that should not be flagged
$DllWhitelist = @(
    'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 
    'gdi32.dll', 'msvcrt.dll', 'advapi32.dll', 'ws2_32.dll',
    'shell32.dll', 'ole32.dll', 'combase.dll', 'bcrypt.dll',
    'crypt32.dll', 'sechost.dll', 'rpcrt4.dll', 'imm32.dll',
    'shcore.dll', 'shlwapi.dll', 'version.dll', 'winmm.dll',
    'mshtml.dll', 'msi.dll', 'msvcp140.dll', 'vcruntime140.dll'
)

# Target browser processes to monitor
$BrowserTargets = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 
                   'iexplore', 'microsoftedge', 'waterfox', 'palemoon')

$ProcessedDlls = @{}

function Test-SuspiciousDLL {
    param(
        [string]$DllName,
        [string]$DllPath,
        [string]$ProcessName
    )
    
    $dllNameLower = $DllName.ToLower()
    $suspicious = $false
    $reasons = @()
    
    # Skip whitelisted system DLLs
    if ($DllWhitelist -contains $dllNameLower) {
        return $null
    }
    
    # Pattern 1: _elf.dll pattern (known malicious pattern)
    if ($dllNameLower -like '*_elf.dll' -or $dllNameLower -match '_elf') {
        $suspicious = $true
        $reasons += "ELF pattern DLL detected"
    }
    
    # Pattern 2: Suspicious .winmd files outside Windows directory
    if ($dllNameLower -like '*.winmd' -and $DllPath -notmatch '\\Windows\\') {
        $suspicious = $true
        $reasons += "WINMD file outside Windows directory"
    }
    
    # Pattern 3: Random hex-named DLLs (common in malware)
    if ($dllNameLower -match '^[a-f0-9]{8,}\.dll$') {
        $suspicious = $true
        $reasons += "Random hex-named DLL detected"
    }
    
    # Pattern 4: DLLs loaded from TEMP directory (excluding browser cache)
    if ($DllPath -match "\\AppData\\Local\\Temp\\" -and 
        $dllNameLower -notlike "chrome_*" -and 
        $dllNameLower -notlike "edge_*" -and
        $dllNameLower -notlike "moz*" -and
        $dllNameLower -notlike "firefox_*") {
        $suspicious = $true
        $reasons += "DLL loaded from TEMP directory"
    }
    
    # Pattern 5: DLLs in browser profile folders with suspicious names
    if ($DllPath -match "\\AppData\\" -and 
        $dllNameLower -notmatch "chrome|edge|firefox|mozilla" -and
        $dllNameLower -like '*.dll') {
        $suspicious = $true
        $reasons += "DLL in browser profile with non-browser name"
    }
    
    # Pattern 6: Unsigned DLLs in browser processes
    if (Test-Path $DllPath) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid" -and $DllPath -notlike "$env:SystemRoot\*") {
                $suspicious = $true
                $reasons += "Unsigned DLL in browser process"
            }
        } catch { }
    }
    
    if ($suspicious) {
        return @{
            Suspicious = $true
            Reasons = $reasons
            Risk = "High"
        }
    }
    
    return $null
}

function Invoke-ElfCatcher {
    $detections = @()
    
    try {
        foreach ($target in $BrowserTargets) {
            try {
                $procs = Get-Process -Name $target -ErrorAction SilentlyContinue
                
                foreach ($proc in $procs) {
                    try {
                        # Scan all loaded modules in the process
                        $modules = $proc.Modules | Where-Object { $_.FileName -like "*.dll" -or $_.FileName -like "*.winmd" }
                        
                        foreach ($mod in $modules) {
                            try {
                                $dllName = [System.IO.Path]::GetFileName($mod.FileName)
                                $dllPath = $mod.FileName
                                
                                # Check if we've already processed this DLL
                                $key = "$($proc.Id):$dllPath"
                                if ($ProcessedDlls.ContainsKey($key)) {
                                    continue
                                }
                                
                                # Test for suspicious DLL
                                $result = Test-SuspiciousDLL -DllName $dllName -DllPath $dllPath -ProcessName $proc.ProcessName
                                
                                if ($result) {
                                    $detections += @{
                                        ProcessId = $proc.Id
                                        ProcessName = $proc.ProcessName
                                        DllName = $dllName
                                        DllPath = $dllPath
                                        BaseAddress = $mod.BaseAddress.ToString()
                                        Reasons = $result.Reasons
                                        Risk = $result.Risk
                                    }
                                    
                                    # Mark as processed
                                    $ProcessedDlls[$key] = Get-Date
                                    
                                    Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2032 `
                                        -Message "ELF CATCHER: Suspicious DLL in $($proc.ProcessName) (PID: $($proc.Id)) - $dllName - $($result.Reasons -join ', ')"
                                }
                            } catch {
                                # Module may have unloaded during iteration
                                continue
                            }
                        }
                    } catch {
                        # Process may have exited during iteration
                        continue
                    }
                }
            } catch {
                # Process not found, continue
                continue
            }
        }
        
        # Periodic cleanup of processed list to prevent memory bloat
        if ($ProcessedDlls.Count -gt 1000) {
            $oldKeys = $ProcessedDlls.Keys | Where-Object {
                ((Get-Date) - $ProcessedDlls[$_]).TotalHours -gt 24
            }
            foreach ($key in $oldKeys) {
                $ProcessedDlls.Remove($key)
            }
        }
        
        if ($detections.Count -gt 0) {
            $logPath = "$env:ProgramData\Antivirus\Logs\ElfCatcher_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|PID:$($_.ProcessId)|$($_.ProcessName)|$($_.DllName)|$($_.DllPath)|$($_.Reasons -join ';')" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) suspicious DLLs in browser processes"
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
                $count = Invoke-ElfCatcher
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
    Start-Module -Config @{ TickInterval = 30 }
}
