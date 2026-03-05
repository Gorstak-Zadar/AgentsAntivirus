# Firewall Rule Monitoring Module
# Monitors firewall rules for suspicious changes

param([hashtable]$ModuleConfig)

$ModuleName = "FirewallRuleMonitoring"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 60 }
$BaselineRules = @{}

function Initialize-FirewallBaseline {
    try {
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        
        foreach ($rule in $rules) {
            $key = "$($rule.Name)|$($rule.Direction)|$($rule.Action)"
            if (-not $BaselineRules.ContainsKey($key)) {
                $BaselineRules[$key] = @{
                    Name = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    FirstSeen = Get-Date
                }
            }
        }
    } catch { }
}

function Invoke-FirewallRuleMonitoring {
    $detections = @()
    
    try {
        # Get current firewall rules
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        
        # Check for new or modified rules
        foreach ($rule in $rules) {
            $key = "$($rule.Name)|$($rule.Direction)|$($rule.Action)"
            
            if (-not $BaselineRules.ContainsKey($key)) {
                # New rule detected
                $detections += @{
                    RuleName = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    Type = "New Firewall Rule"
                    Risk = "Medium"
                }
                
                # Update baseline
                $BaselineRules[$key] = @{
                    Name = $rule.Name
                    Direction = $rule.Direction
                    Action = $rule.Action
                    Enabled = $rule.Enabled
                    FirstSeen = Get-Date
                }
            } else {
                # Check if rule was modified
                $baseline = $BaselineRules[$key]
                if ($rule.Enabled -ne $baseline.Enabled) {
                    $detections += @{
                        RuleName = $rule.Name
                        OldState = $baseline.Enabled
                        NewState = $rule.Enabled
                        Type = "Firewall Rule State Changed"
                        Risk = "High"
                    }
                    
                    $baseline.Enabled = $rule.Enabled
                }
            }
        }
        
        # Check for suspicious firewall rules
        foreach ($rule in $rules) {
            try {
                $ruleFilters = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $ruleAppFilters = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                
                # Check for rules allowing all traffic
                if ($ruleFilters) {
                    if ($ruleFilters.RemoteAddress -eq "*" -and $rule.Action -eq "Allow") {
                        $detections += @{
                            RuleName = $rule.Name
                            RemoteAddress = $ruleFilters.RemoteAddress
                            Type = "Firewall Rule Allows All Traffic"
                            Risk = "High"
                        }
                    }
                }
                
                # Check for rules allowing unsigned applications
                if ($ruleAppFilters -and $ruleAppFilters.Program) {
                    foreach ($program in $ruleAppFilters.Program) {
                        if ($program -and (Test-Path $program)) {
                            $sig = Get-AuthenticodeSignature -FilePath $program -ErrorAction SilentlyContinue
                            if ($sig.Status -ne "Valid" -and $rule.Action -eq "Allow") {
                                $detections += @{
                                    RuleName = $rule.Name
                                    Program = $program
                                    Type = "Firewall Rule Allows Unsigned Application"
                                    Risk = "Medium"
                                }
                            }
                        }
                    }
                }
                
                # Check for rules with unusual port ranges
                $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                if ($portFilters) {
                    if ($portFilters.LocalPort -eq "*" -or 
                        ($portFilters.LocalPort -is [Array] -and $portFilters.LocalPort.Count -gt 100)) {
                        $detections += @{
                            RuleName = $rule.Name
                            LocalPort = $portFilters.LocalPort
                            Type = "Firewall Rule with Unusual Port Range"
                            Risk = "Medium"
                        }
                    }
                }
            } catch {
                continue
            }
        }
        
        # Check for firewall service status
        try {
            $fwService = Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" -ErrorAction SilentlyContinue
            
            if ($fwService -and $fwService.State -ne "Running") {
                $detections += @{
                    ServiceState = $fwService.State
                    Type = "Windows Firewall Service Not Running"
                    Risk = "Critical"
                }
            }
        } catch { }
        
        # Check for firewall profiles
        try {
            $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            
            foreach ($profile in $profiles) {
                if ($profile.Enabled -eq $false) {
                    $detections += @{
                        ProfileName = $profile.Name
                        Type = "Firewall Profile Disabled"
                        Risk = "Critical"
                    }
                }
            }
        } catch { }
        
        if ($detections.Count -gt 0) {
            foreach ($detection in $detections) {
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2024 `
                    -Message "FIREWALL RULE MONITORING: $($detection.Type) - $($detection.RuleName -or $detection.ProfileName)"
            }
            
            $logPath = "$env:ProgramData\Antivirus\Logs\FirewallRule_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.RuleName -or $_.ProfileName)" |
                    Add-Content -Path $logPath
            }
            
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) firewall rule anomalies"
        }
    } catch {
        Write-Output "ERROR:$ModuleName`:$_"
    }
    
    return $detections.Count
}

function Start-Module {
    param([hashtable]$Config)
    
    Initialize-FirewallBaseline
    Start-Sleep -Seconds 10
    
    while ($true) {
        try {
            $now = Get-Date
            if (($now - $LastTick).TotalSeconds -ge $TickInterval) {
                $count = Invoke-FirewallRuleMonitoring
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
