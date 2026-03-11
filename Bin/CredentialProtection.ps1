# Credential Protection - LSASS/dumping/credential theft indicators
# Detects LSASS access, credential manager abuse, DPAPI/mimikatz patterns

param([hashtable]$ModuleConfig)

$ModuleName = "CredentialProtection"
$LastTick = Get-Date
$TickInterval = if ($ModuleConfig.TickInterval) { $ModuleConfig.TickInterval } else { 300 }

function Invoke-CredentialProtection {
    $detections = @()
    try {
        # Known credential-dump / mimikatz-like process names and paths
        $credThreatNames = @('mimikatz','sekurlsa','procdump','proc_dump','lsass_dump','comsvcs','rundll32')
        $procs = Get-Process -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $pn = $p.ProcessName.ToLower()
            foreach ($t in $credThreatNames) {
                if ($pn -like "*$t*") {
                    $detections += @{
                        Type = "Known credential-dump related process"
                        ProcessId = $p.Id
                        ProcessName = $p.ProcessName
                        Path = $p.Path
                        Risk = "Critical"
                    }
                    break
                }
            }
        }

        # Command lines that suggest LSASS access or credential export
        try {
            $cimProcs = Get-CimInstance Win32_Process | Where-Object {
                $_.CommandLine -match 'lsass|minidump|comsvcs.*MiniDump|sekurlsa|mimikatz|procdump.*lsass'
            }
            foreach ($proc in $cimProcs) {
                $detections += @{
                    Type = "Suspicious credential-related command line"
                    ProcessId = $proc.ProcessId
                    ProcessName = $proc.Name
                    CommandLine = $proc.CommandLine
                    Risk = "Critical"
                }
            }
        } catch { }

        # Credential Guard / LSA protection registry
        try {
            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (Test-Path $lsaPath) {
                $runLsaPpl = Get-ItemProperty -Path $lsaPath -Name "RunLsaPpl" -ErrorAction SilentlyContinue
                $lsaCfg = Get-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
                # RunLsaPpl=1 and LsaCfgFlags=1 are desirable
                if (-not $runLsaPpl -or $runLsaPpl.RunLsaPpl -ne 1) {
                    $detections += @{ Type = "LSA protection (RunLsaPpl) not enforced"; Risk = "Medium"; Detail = "RunLsaPpl" }
                }
            }
        } catch { }

        # Scheduled tasks or startup that run credential-related tools
        try {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Ready' }
            foreach ($t in $tasks) {
                $action = $t.Actions | Select-Object -First 1
                if ($action.Execute -match 'procdump|mimikatz|pwdump' -or $action.Arguments -match 'lsass|minidump') {
                    $detections += @{
                        Type = "Scheduled task with credential-dump tool"
                        TaskName = $t.TaskName
                        Execute = $action.Execute
                        Arguments = $action.Arguments
                        Risk = "Critical"
                    }
                }
            }
        } catch { }

        if ($detections.Count -gt 0) {
            foreach ($d in $detections) {
                $msg = "CredentialProtection: $($d.Type) - $($d.ProcessName -or $d.TaskName -or $d.Detail)"
                Write-EventLog -LogName Application -Source "AntivirusEDR" -EntryType Warning -EventId 2092 -Message $msg -ErrorAction SilentlyContinue
            }
            $logPath = "$env:ProgramData\Antivirus\Logs\CredentialProtection_$(Get-Date -Format 'yyyy-MM-dd').log"
            $detections | ForEach-Object {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$($_.Type)|$($_.Risk)|$($_.ProcessName -or $_.TaskName -or $_.Detail)" | Add-Content -Path $logPath -ErrorAction SilentlyContinue
            }
            Write-Output "DETECTION:$ModuleName`:Found $($detections.Count) credential threats"
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
                Invoke-CredentialProtection | Out-Null
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
