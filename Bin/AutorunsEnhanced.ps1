#Requires -Version 5.1

<#
.SYNOPSIS
    AutorunsEnhanced - Autoruns-style enumeration with auto-removal of unverified entries and untrusted font check.
.DESCRIPTION
    Like Sysinternals Autoruns: enumerates all auto-start locations (Run, services, tasks, startup folders,
    Winlogon, etc.). Automatically removes entries that fail signature verification (unverified).
    Unlike Autoruns: also checks for untrusted fonts (fonts outside C:\Windows\Fonts).
.NOTES
    Author: Gorstak | Part of AgentsAntivirus
    Run as Administrator for full enumeration and removal.
#>

param(
    [switch]$RemoveUnverified,
    [switch]$ReportOnly,
    [switch]$SkipFonts
)

$ErrorActionPreference = "SilentlyContinue"

$trustedFontPath = "$env:windir\Fonts"
$userFontPaths = @(
    "$env:LOCALAPPDATA\Microsoft\Windows\Fonts",
    "$env:APPDATA\Microsoft\Windows\Fonts"
)

$autorunLocations = @(
    @{ Name = "HKLM Run"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Type = "Registry" },
    @{ Name = "HKCU Run"; Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Type = "Registry" },
    @{ Name = "HKLM RunOnce"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Type = "Registry" },
    @{ Name = "HKCU RunOnce"; Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Type = "Registry" },
    @{ Name = "WOW6432 Run"; Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Type = "Registry" },
    @{ Name = "Explorer Run"; Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Policies\Explorer\Run"; Type = "Registry" },
    @{ Name = "Winlogon"; Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Type = "Registry" },
    @{ Name = "Startup All Users"; Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"; Type = "Folder" },
    @{ Name = "Startup Current User"; Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Type = "Folder" },
    @{ Name = "Scheduled Tasks"; Path = "C:\Windows\System32\Tasks"; Type = "Tasks" }
)

function Test-SignatureVerified {
    param([string]$FilePath)
    if (-not $FilePath -or -not (Test-Path $FilePath -PathType Leaf)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        return ($sig -and $sig.Status -eq "Valid")
    }
    catch { return $false }
}

function Get-ExecutableFromValue {
    param([string]$Value)
    if (-not $Value) { return $null }
    $v = $Value.Trim()
    if ($v -match '^"([^"]+)"') { return $Matches[1].Trim() }
    if ($v -match '^([^\s]+\.(exe|dll|com|bat|cmd|ps1|vbs|js))') { return $Matches[1].Trim() }
    $first = ($v -split '\s+')[0]
    if ($first -match '\.(exe|dll|com|bat|cmd)$') { return $first }
    return $null
}

function Resolve-ExpandPath {
    param([string]$Path)
    if (-not $Path) { return $null }
    $p = $Path
    $p = $p -replace '%windir%', $env:windir
    $p = $p -replace '%systemroot%', $env:windir
    $p = $p -replace '%programfiles%', $env:ProgramFiles
    $p = $p -replace '%programfiles\(x86\)%', ${env:ProgramFiles(x86)}
    $p = $p -replace '%localappdata%', $env:LOCALAPPDATA
    $p = $p -replace '%appdata%', $env:APPDATA
    $p = $p -replace '%temp%', $env:TEMP
    $p = $p -replace '%tmp%', $env:TEMP
    if (Test-Path $p -ErrorAction SilentlyContinue) { return $p }
    return $Path
}

function Invoke-RegistryAutorunScan {
    $results = @()
    foreach ($loc in $autorunLocations | Where-Object { $_.Type -eq "Registry" }) {
        if (-not (Test-Path $loc.Path)) { continue }
        try {
            $props = Get-ItemProperty -Path $loc.Path -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $val = $_.Value
                $exe = Get-ExecutableFromValue -Value $val
                $resolved = Resolve-ExpandPath -Path $exe
                $verified = Test-SignatureVerified -FilePath $resolved
                $results += [PSCustomObject]@{
                    Location = $loc.Name
                    Path     = $loc.Path
                    Name     = $_.Name
                    Value    = $val
                    FilePath = $resolved
                    Verified = $verified
                    EntryType = "Registry"
                }
            }
        }
        catch { }
    }
    return $results
}

function Invoke-FolderAutorunScan {
    $results = @()
    foreach ($loc in $autorunLocations | Where-Object { $_.Type -eq "Folder" }) {
        if (-not (Test-Path $loc.Path)) { continue }
        try {
            Get-ChildItem -Path $loc.Path -File -ErrorAction SilentlyContinue | ForEach-Object {
                $fp = $_.FullName
                $verified = Test-SignatureVerified -FilePath $fp
                $results += [PSCustomObject]@{
                    Location  = $loc.Name
                    Path      = $loc.Path
                    Name      = $_.Name
                    Value     = $fp
                    FilePath  = $fp
                    Verified  = $verified
                    EntryType = "Folder"
                }
            }
        }
        catch { }
    }
    return $results
}

function Invoke-TaskAutorunScan {
    $results = @()
    $tasks = Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
    foreach ($t in $tasks) {
        $act = ($t.Actions | Select-Object -First 1).Execute
        $arg = ($t.Actions | Select-Object -First 1).Arguments
        $fp = Resolve-ExpandPath -Path $act
        $verified = $false
        if ($act -match '\.(exe|dll|com)$') { $verified = Test-SignatureVerified -FilePath $fp }
        else { $verified = $true }
        $results += [PSCustomObject]@{
            Location  = "Scheduled Tasks"
            Path      = $t.TaskPath
            Name      = $t.TaskName
            Value     = "$act $arg"
            FilePath  = $fp
            Verified  = $verified
            EntryType = "Task"
        }
    }
    return $results
}

function Invoke-FontScan {
    $untrusted = @()
    foreach ($up in $userFontPaths) {
        if (-not (Test-Path $up)) { continue }
        Get-ChildItem -Path $up -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Extension -match '\.(ttf|otf|ttc)$'
        } | ForEach-Object {
            $untrusted += [PSCustomObject]@{ Path = $_.FullName; Name = $_.Name; Reason = "Font outside trusted path ($trustedFontPath)" }
        }
    }
    $profileFonts = "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Fonts"
    if (Test-Path $profileFonts) {
        Get-ChildItem -Path $profileFonts -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Extension -match '\.(ttf|otf|ttc)$'
        } | ForEach-Object {
            $untrusted += [PSCustomObject]@{ Path = $_.FullName; Name = $_.Name; Reason = "Font in user profile (untrusted)" }
        }
    }
    return $untrusted
}

$regEntries = Invoke-RegistryAutorunScan
$folderEntries = Invoke-FolderAutorunScan
$taskEntries = Invoke-TaskAutorunScan
$allEntries = $regEntries + $folderEntries + $taskEntries
$unverified = $allEntries | Where-Object { -not $_.Verified }
$fontIssues = if (-not $SkipFonts) { Invoke-FontScan } else { @() }

Write-Host "AutorunsEnhanced - Unverified: $($unverified.Count) | Untrusted fonts: $($fontIssues.Count)" -ForegroundColor Cyan
foreach ($e in $unverified) {
    $status = if ($RemoveUnverified) { "REMOVING" } else { "UNVERIFIED" }
    Write-Host "[$status] $($e.Location) | $($e.Name) | $($e.Value)" -ForegroundColor $(if ($RemoveUnverified) { "Red" } else { "Yellow" })
}
foreach ($f in $fontIssues) { Write-Host "[UNTRUSTED] $($f.Path)" -ForegroundColor Yellow }

if ($RemoveUnverified -and -not $ReportOnly) {
    foreach ($e in $unverified) {
        try {
            if ($e.EntryType -eq "Registry") {
                Remove-ItemProperty -Path $e.Path -Name $e.Name -Force -ErrorAction Stop
                Write-Host "Removed: $($e.Path)\$($e.Name)" -ForegroundColor Green
            }
            elseif ($e.EntryType -eq "Folder") {
                Remove-Item -Path $e.FilePath -Force -ErrorAction Stop
                Write-Host "Removed: $($e.FilePath)" -ForegroundColor Green
            }
            elseif ($e.EntryType -eq "Task") {
                Unregister-ScheduledTask -TaskName $e.Name -TaskPath $e.Path -Confirm:$false -ErrorAction Stop
                Write-Host "Removed task: $($e.Path)$($e.Name)" -ForegroundColor Green
            }
        }
        catch { Write-Host "Failed: $($e.Name): $_" -ForegroundColor Red }
    }
}
