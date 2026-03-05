# WMI Persistence Detection Module
# Detects WMI-based persistence mechanisms

param([hashtable]$ModuleConfig)

$ModuleName = "WMIPersistenceDetection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }

function Invoke-WMIPersistenceScan {
    $detections = @()
    
    try {
        # Check WMI Event Consumers
        $eventConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
        
        foreach ($consumer in $eventConsumers) {
            # Check for suspicious consumer types
            if ($consumer.__CLASS -match 'ActiveScript|CommandLine') {
                $suspicious = $false
                $details = @{}
                
                # Check CommandLineEventConsumer
                if ($consumer.__CLASS -eq '__EventConsumer') {
                    $cmdLine = $consumer.CommandLineTemplate
                    if ($cmdLine) {
                        $details.CommandLine = $cmdLine
                        # Check for suspicious commands
                        if ($cmdLine -match 'powershell|cmd|certutil|bitsadmin|wmic' -or
                            $cmdLine -match 'http|https|ftp' -or
                            $cmdLine -match '-encodedcommand|-nop|-w.*hidden') {
                            $suspicious = $true
                        }
                    }
                }
                
                # Check ActiveScriptEventConsumer
                if ($consumer.__CLASS -match 'ActiveScript') {
                    $script = $consumer.ScriptText
                    if ($script -and ($script.Length -gt 1000 -or 
                        $script -match 'wscript|eval|exec|shell')) {
                        $suspicious = $true
                        $details.ScriptLength = $script.Length
                    }
                }
                
                if ($suspicious) {
                    $detections += @{
                        ConsumerName = $consumer.Name
                        ConsumerClass = $consumer.__CLASS
                        Details = $details
                        Risk = "High"
                    }
                }
            }
        }
        
        # Check WMI Event Filters
        $eventFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        
        foreach ($filter in $eventFilters) {
            $query = $filter.Query
            if ($query) {
                # Check for suspicious event filters
                if ($query -match 'SELECT.*FROM.*__InstanceModificationEvent' -or
                    $query -match 'SELECT.*FROM.*Win32_ProcessStartTrace') {
                    $filterName = $filter.Name
                    
                    # Check if filter is bound to suspicious consumer
                    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                        Where-Object { $_.Filter -like "*$filterName*" }
                    
                    if ($bindings) {
                        $detections += @{
                            FilterName = $filterName
                            Query = $query
                            Type = "Event Filter Binding"
                            Risk = "Medium"
                        }
                    }
                }
            }
        }
        
        # Check for suspicious WMI namespaces
        try {
            $namespaces = Get-CimInstance -Namespace root -ClassName __Namespace -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^[a-f0-9]{32}$' }
            
            foreach ($ns in $namespaces) {
                $detections += @{
                    Namespace = $ns.Name
                    Type = "Suspicious WMI Namespace"
                    Risk = "High"
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2006 `
                    -Message "WMI PERSISTENCE DETECTED: $($detection.ConsumerName -or $detection.FilterName -or $detection.Namespace) - $($detection.Type)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\WMIPersistence_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.ConsumerName -or $_.FilterName)|$($_.Type)|$($_.Risk)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) WMI persistence mechanisms"
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
                $count = Invoke-WMIPersistenceScan
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
