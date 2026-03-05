# MITRE ATT&CK Mapping
# Maps detections to MITRE ATT&CK and logs stats

param([hashtable]$ModuleConfig)

$ModuleName = "MitreMapping"

$TechniqueMap = @{
    "HashDetection" = "T1204"
    "LOLBin" = "T1218"
    "ProcessAnomaly" = "T1055"
    "AMSIBypass" = "T1562.006"
    "CredentialDump" = "T1003"
    "MemoryAcquisition" = "T1119"
    "WMIPersistence" = "T1547.003"
    "ScheduledTask" = "T1053.005"
    "RegistryPersistence" = "T1547.001"
    "DLLHijacking" = "T1574.001"
    "TokenManipulation" = "T1134"
    "ProcessHollowing" = "T1055.012"
    "Keylogger" = "T1056.001"
    "Ransomware" = "T1486"
    "NetworkAnomaly" = "T1041"
    "Beacon" = "T1071"
    "DNSExfiltration" = "T1048"
    "Rootkit" = "T1014"
    "Clipboard" = "T1115"
    "ShadowCopy" = "T1490"
    "USB" = "T1052"
    "Webcam" = "T1125"
    "AttackTools" = "T1588"
    "AdvancedThreat" = "T1204"
    "EventLog" = "T1562.006"
    "FirewallRule" = "T1562.004"
    "Fileless" = "T1059"
    "MemoryScanning" = "T1003"
    "CodeInjection" = "T1055"
    "DataExfiltration" = "T1048"
    "FileEntropy" = "T1204"
    "Honeypot" = "T1204"
    "LateralMovement" = "T1021"
    "ProcessCreation" = "T1059"
    "YaraDetection" = "T1204"
    "IdsDetection" = "T1059"
}

function Map-ToMitre {
    param([string]$DetectionSource, [string]$Details = "")
    $tech = $TechniqueMap[$DetectionSource]
    if ($tech) {
        $entry = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            DetectionSource = $DetectionSource
            MITRETechnique = $tech
            Details = $Details
        }
        $logPath = "$env:ProgramData\Antivirus\Logs\mitre_mapping_$(Get-Date -Format 'yyyy-MM-dd').log"
        "$($entry.Timestamp)|$($entry.DetectionSource)|$($entry.MITRETechnique)|$($entry.Details)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
        return $tech
    }
    return $null
}

function Invoke-MitreMapping {
    $mapped = 0
    try {
        $logPath = "$env:ProgramData\Antivirus\Logs"
        if (-not (Test-Path $logPath)) { return 0 }
        $today = Get-Date -Format 'yyyy-MM-dd'
        $sourceMap = @{
            'HashDetection' = 'HashDetection'; 'Hash' = 'HashDetection'; 'THREAT' = 'HashDetection'
            'LOLBinDetection' = 'LOLBin'; 'LOLBin' = 'LOLBin'
            'ProcessAnomaly' = 'ProcessAnomaly'; 'ProcessAnomalyDetection' = 'ProcessAnomaly'
            'AMSIBypass' = 'AMSIBypass'; 'AMSIBypassDetection' = 'AMSIBypass'
            'CredentialDump' = 'CredentialDump'; 'CredentialDumpDetection' = 'CredentialDump'
            'MemoryAcquisition' = 'MemoryAcquisition'; 'MemoryAcquisitionDetection' = 'MemoryAcquisition'
            'WMIPersistence' = 'WMIPersistence'; 'WMIPersistenceDetection' = 'WMIPersistence'
            'ScheduledTask' = 'ScheduledTask'; 'ScheduledTaskDetection' = 'ScheduledTask'
            'RegistryPersistence' = 'RegistryPersistence'; 'RegistryPersistenceDetection' = 'RegistryPersistence'
            'DLLHijacking' = 'DLLHijacking'; 'DLLHijackingDetection' = 'DLLHijacking'
            'TokenManipulation' = 'TokenManipulation'; 'TokenManipulationDetection' = 'TokenManipulation'
            'ProcessHollowing' = 'ProcessHollowing'; 'ProcessHollowingDetection' = 'ProcessHollowing'
            'Keylogger' = 'Keylogger'; 'KeyloggerDetection' = 'Keylogger'
            'Ransomware' = 'Ransomware'; 'RansomwareDetection' = 'Ransomware'
            'Beacon' = 'Beacon'; 'BeaconDetection' = 'Beacon'
            'NetworkAnomaly' = 'NetworkAnomaly'; 'NetworkAnomalyDetection' = 'NetworkAnomaly'
            'DNSExfiltration' = 'DNSExfiltration'; 'DNSExfiltrationDetection' = 'DNSExfiltration'
            'Rootkit' = 'Rootkit'; 'RootkitDetection' = 'Rootkit'
            'ShadowCopy' = 'ShadowCopy'; 'ShadowCopyMonitoring' = 'ShadowCopy'
            'USB' = 'USB'; 'USBMonitoring' = 'USB'
            'Webcam' = 'Webcam'; 'WebcamGuardian' = 'Webcam'
            'AttackTools' = 'AttackTools'; 'AttackToolsDetection' = 'AttackTools'
            'EventLog' = 'EventLog'; 'EventLogMonitoring' = 'EventLog'
            'Fileless' = 'Fileless'; 'FilelessDetection' = 'Fileless'
            'CodeInjection' = 'CodeInjection'; 'CodeInjectionDetection' = 'CodeInjection'
            'DataExfiltration' = 'DataExfiltration'; 'DataExfiltrationDetection' = 'DataExfiltration'
            'FileEntropy' = 'FileEntropy'; 'FileEntropyDetection' = 'FileEntropy'
            'LateralMovement' = 'LateralMovement'; 'LateralMovementDetection' = 'LateralMovement'
            'ProcessCreation' = 'ProcessCreation'; 'ProcessCreationDetection' = 'ProcessCreation'
            'YaraDetection' = 'YaraDetection'; 'IdsDetection' = 'IdsDetection'
        }
        $logFiles = Get-ChildItem -Path $logPath -Filter "*_$today.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch 'mitre_mapping|ResponseEngine' }
        foreach ($lf in $logFiles) {
            $entries = Get-Content $lf.FullName -Tail 20 -ErrorAction SilentlyContinue
            foreach ($line in $entries) {
                if ($line -match '\|') {
                    $parts = $line -split '\|'
                    $src = $parts[1] -replace 'Detection|Scan|Monitoring', ''
                    $key = $sourceMap.Keys | Where-Object { $parts[1] -like "*$_*" -or $_.ToString() -eq $src } | Select-Object -First 1
                    $mapKey = if ($key) { $sourceMap[$key] } else { $parts[1] }
                    if ($TechniqueMap[$mapKey] -and $line -notmatch 'mitre_mapping') {
                        $tech = Map-ToMitre -DetectionSource $mapKey -Details ($parts -join '|')
                        if ($tech) { $mapped++ }
                    }
                }
            }
        }
        if ($mapped -gt 0) { Write-Output "STATS:$ModuleName`:Mapped $mapped detections to MITRE" }
    } catch { Write-Output "ERROR:$ModuleName`:$_" }
    return $mapped
}

function Start-Module {
    param([hashtable]$Config)
    while ($true) {
        Invoke-MitreMapping | Out-Null
        Start-Sleep -Seconds 60
    }
}

if (-not $ModuleConfig) { Start-Module -Config @{} }
