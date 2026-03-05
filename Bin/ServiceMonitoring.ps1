# Service Monitoring Module
# Monitors Windows services for suspicious activity

param([hashtable]$ModuleConfig)

$ModuleName = "ServiceMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }
$BaselineServices = @{}

function Initialize-ServiceBaseline {
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        
        foreach ($svc in $services) {
            $key = "$($svc.Name)|$($svc.PathName)"
            if (-not $BaselineServices.ContainsKey($key)) {
                $BaselineServices[$key] = @{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    PathName = $svc.PathName
                    State = $svc.State
                    StartMode = $svc.StartMode
                    StartName = $svc.StartName
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Invoke-ServiceMonitoring {
    $detections = @()
    
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        
        foreach ($svc in $services) {
            $key = "$($svc.Name)|$($svc.PathName)"
            
            # Check for new services
            if (-not $BaselineServices.ContainsKey($key)) {
                $detections += @{
                    ServiceName = $svc.Name
                    DisplayName = $svc.DisplayName
                    PathName = $svc.PathName
                    State = $svc.State
                    StartMode = $svc.StartMode
                    Type = "New Service Detected"
                    Risk = "High"
                }
                
                # Update baseline
                $BaselineServices[$key] = @{
                    Name = $svc.Name
                    DisplayName = $svc.DisplayName
                    PathName = $svc.PathName
                    State = $svc.State
                    StartMode = $svc.StartMode
                    StartName = $svc.StartName
                    FirstSeen = Get-Date
                }
            } else {
                # Check for service state changes
                $baseline = $BaselineServices[$key]
                if ($svc.State -ne $baseline.State) {
                    $detections += @{
                        ServiceName = $svc.Name
                        OldState = $baseline.State
                        NewState = $svc.State
                        Type = "Service State Changed"
                        Risk = "Medium"
                    }
                    $baseline.State = $svc.State
                }
            }
            
            # Check for suspicious service properties
            if ($svc.PathName -and (Test-Path $svc.PathName)) {
                # Check for unsigned service executables
                $sig = Get-AuthenticodeSignature -FilePath $svc.PathName -ErrorAction SilentlyContinue
                if ($sig.Status -ne "Valid") {
                    $detections += @{
                        ServiceName = $svc.Name
                        PathName = $svc.PathName
                        Type = "Unsigned Service Executable"
                        Risk = "High"
                    }
                }
                
                # Check for services not in system directories
                if ($svc.PathName -notlike "$env:SystemRoot\*" -and 
                    $svc.PathName -notlike "$env:ProgramFiles*") {
                    $detections += @{
                        ServiceName = $svc.Name
                        PathName = $svc.PathName
                        Type = "Service Executable Outside System/Program Directories"
                        Risk = "Medium"
                    }
                }
                
                # Check for services with suspicious command line arguments
                if ($svc.PathName -match 'powershell|cmd|wscript|cscript|http') {
                    $detections += @{
                        ServiceName = $svc.Name
                        PathName = $svc.PathName
                        Type = "Service with Suspicious Command Line"
                        Risk = "High"
                    }
                }
            }
            
            # Check for services running as SYSTEM with suspicious paths
            if ($svc.StartName -eq "LocalSystem" -or $svc.StartName -eq "NT AUTHORITY\SYSTEM") {
                if ($svc.PathName -notlike "$env:SystemRoot\*") {
                    $detections += @{
                        ServiceName = $svc.Name
                        StartName = $svc.StartName
                        PathName = $svc.PathName
                        Type = "SYSTEM Service Outside System Directory"
                        Risk = "Critical"
                    }
                }
            }
            
            # Check for services with unusual display names
            if ($svc.DisplayName -match 'update|installer|system|security|windows' -and
                $svc.Name -notmatch '^[A-Z][a-z]') {
                # Suspicious display name pattern
                $detections += @{
                    ServiceName = $svc.Name
                    DisplayName = $svc.DisplayName
                    Type = "Service with Suspicious Display Name"
                    Risk = "Medium"
                }
            }
        }
        
        # Check for stopped critical services
        $criticalServices = @("WinDefend", "SecurityHealthService", "MpsSvc", "BITS")
        foreach ($criticalSvc in $criticalServices) {
            $svc = $services | Where-Object { $_.Name -eq $criticalSvc } | Select-Object -First 1
            if ($svc -and $svc.State -ne "Running") {
                $detections += @{
                    ServiceName = $svc.Name
                    State = $svc.State
                    Type = "Critical Service Stopped"
                    Risk = "High"
                }
            }
        }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2025 `
                    -Message "SERVICE MONITORING: $($detection.Type) - $($detection.ServiceName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\ServiceMonitoring_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ServiceName)|$($_.PathName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) service anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    Initialize-ServiceBaseline
    Start-Sleep -Seconds 10
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-ServiceMonitoring
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
    Start-Module -Config @{ TickInterval = 60 }
}
