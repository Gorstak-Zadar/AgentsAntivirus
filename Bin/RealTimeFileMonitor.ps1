# Real-Time File Monitor
# FileSystemWatcher for exe/dll/sys/winmd on fixed and removable drives

param([hashtable]$ModuleConfig)

$ModuleName = "RealTimeFileMonitor"
$script:Watchers = @()
$script:WatchersInitialized = $false

function Start-RealtimeMonitor {
    $extensions = @("*.exe", "*.dll", "*.sys", "*.winmd")
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
    
    foreach ($drive in $drives) {
        $root = $drive.Root
        if (-not (Test-Path $root)) { continue }
        
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $root
            $watcher.IncludeSubdirectories = $true
            $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
            
            $action = {
                $path = $Event.SourceEventArgs.FullPath
                $ext = [System.IO.Path]::GetExtension($path).ToLower()
                if ($ext -in @(".exe", ".dll", ".sys", ".winmd")) {
                    Start-Sleep -Seconds 1
                    if (Test-Path $path) {
                        try {
                            $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            $logPath = "$env:ProgramData\Antivirus\Logs\realtime_monitor_$(Get-Date -Format 'yyyy-MM-dd').log"
                            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|Created/Changed|$path|$hash" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
                            Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2090 -Message "REAL-TIME: $path" -ErrorAction SilentlyContinue
                        } catch { }
                    }
                }
            }
            
            Register-ObjectEvent $watcher Created -Action $action | Out-Null
            Register-ObjectEvent $watcher Changed -Action $action | Out-Null
            $watcher.EnableRaisingEvents = $true
            $script:Watchers += $watcher
            Write-Output "STATS:$ModuleName`:Watching $root"
        } catch {
            Write-Output "ERROR:$ModuleName`:Failed to watch $root - $_"
        }
    }
    
    Write-Output "STATS:$ModuleName`:Started with $($script:Watchers.Count) watchers"
}

function Invoke-RealTimeFileMonitor {
    if (-not $script:WatchersInitialized) {
        Start-RealtimeMonitor | Out-Null
        $script:WatchersInitialized = $true
    }
    return $script:Watchers.Count
}

function Start-Module {
    param([hashtable]$Config)
    Start-RealtimeMonitor | Out-Null
    $script:WatchersInitialized = $true
    while ($true) { Start-Sleep -Seconds 60 }
}

if (-not $ModuleConfig) { Start-Module -Config @{} }
