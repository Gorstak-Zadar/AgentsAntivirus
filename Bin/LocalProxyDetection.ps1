# Local Proxy Detection - Shadow TLS / local proxy pattern
# Detects processes listening on localhost with outbound 443 (TLS camouflage / proxy)

param([hashtable]$ModuleConfig)

$ModuleName = "LocalProxyDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-LocalProxyDetection {
    $detections = @()
    try {
        # Established TCP connections: local port and remote port 443
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        $localListen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

        # Build set of PIDs listening on 127.0.0.1 or ::1
        $listeners = $localListen | Where-Object {
            $_.LocalAddress -match '^127\.|^::1$' -and $_.OwningProcess -gt 0
        } | Group-Object OwningProcess

        foreach ($g in $listeners) {
            $pid = $g.Name
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if (-not $proc) { continue }
            # Same process has outbound 443?
            $out443 = $conns | Where-Object { $_.OwningProcess -eq $pid -and $_.RemotePort -eq 443 }
            if ($out443.Count -eq 0) { continue }
            # Exclude browser and known good
            $exclude = @('svchost','msedge','chrome','firefox','opera','brave','iexplore','ApplicationFrameHost')
            if ($proc.ProcessName -in $exclude) { continue }
            $detections += @{
                Type = "Local proxy pattern (listen local + outbound 443)"
                ProcessId = $pid
                ProcessName = $proc.ProcessName
                Path = $proc.Path
                LocalPorts = ($g.Group.LocalPort | Sort-Object -Unique) -join ','
                Risk = "High"
            }
        }

        # Proxy environment variables pointing to localhost
        $proxyVars = @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy')
        foreach ($v in $proxyVars) {
            $val = [Environment]::GetEnvironmentVariable($v, 'Process')
            if ([string]::IsNullOrEmpty($val)) { $val = [Environment]::GetEnvironmentVariable($v, 'User') }
            if ([string]::IsNullOrEmpty($val)) { $val = [Environment]::GetEnvironmentVariable($v, 'Machine') }
            if ($val -and $val -match '127\.0\.0\.1|localhost|::1') {
                $detections += @{
                    Type = "System proxy set to localhost"
                    Variable = $v
                    Value = $val
                    Risk = "Medium"
                }
            }
        }

        # WinHTTP proxy registry (often used by malware)
        try {
            $proxyReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer" -ErrorAction SilentlyContinue
            if ($proxyReg -and $proxyReg.ProxyServer -match '127\.0\.0\.1|localhost') {
                $detections += @{
                    Type = "Machine proxy registry points to localhost"
                    ProxyServer = $proxyReg.ProxyServer
                    Risk = "High"
                }
            }
        } catch { }

        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                $msg = "LocalProxyDetection: $($d.Type) - $($d.ProcessName -or $d.Variable -or 'Registry')"
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2094 -Message $msg -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\LocalProxyDetection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.Variable -or $_.ProxyServer)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) local proxy indicators"
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
                Invoke-LocalProxyDetection | Out-Null
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
