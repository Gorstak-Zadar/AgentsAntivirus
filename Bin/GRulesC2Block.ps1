# GRulesC2Block.ps1 - GEDR-aligned: parse YARA/Snort-style rule files for IPs/domains, create outbound firewall blocks (C2 blocklist)
# Optional: set $env:GRulesRulePaths to semicolon- or comma-separated paths to .yar or .rules files. If not set, no-ops.

function Invoke-GRulesC2Block {
    param([string]$RulePaths = $env:GRulesRulePaths)
    $ErrorActionPreference = "Stop"
    $BatchSize = 100
    $DisplayNamePrefix = "Block C2 IPs Batch "
    $LogDir = "$env:ProgramData\Antivirus\Logs"
    $LogFile = "$LogDir\GRulesC2Block_$(Get-Date -Format 'yyyy-MM-dd').log"

    if ([string]::IsNullOrWhiteSpace($RulePaths)) { return }

    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

    function Write-GRulesLog {
        param([string]$Message)
        $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|$Message"
        try { $line | Out-File -FilePath $LogFile -Append -Encoding UTF8 } catch {}
    }

    $paths = $RulePaths -split '[;,]+' | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }
    if ($paths.Count -eq 0) { return }

    $allIps = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $ipRegex = [regex]'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    $domainRegex = [regex]'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

    foreach ($path in $paths) {
        if (-not (Test-Path $path)) { continue }
        try {
            $content = Get-Content -Path $path -Raw -ErrorAction Stop
            foreach ($m in $ipRegex.Matches($content)) {
                if ($m.Success -and $m.Value) { [void]$allIps.Add($m.Value) }
            }
            foreach ($m in $domainRegex.Matches($content)) {
                if (-not $m.Success -or [string]::IsNullOrEmpty($m.Value)) { continue }
                $domain = $m.Value
                if ($domain.IndexOf('.') -ge 0 -and $domain.Length -ge 4) {
                    try {
                        [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object {
                            if ($_.IPAddressToString) { [void]$allIps.Add($_.IPAddressToString) }
                        }
                    } catch {}
                }
            }
        } catch {
            Write-GRulesLog "Parse $path : $_"
        }
    }

    if ($allIps.Count -eq 0) { return }

    $out = netsh advfirewall firewall show rule name=all 2>&1 | Out-String
    $matches = [regex]::Matches($out, 'Rule Name:\s*(Block C2 IPs Batch \d+)')
    $names = @($matches | ForEach-Object { $_.Groups[1].Value.Trim() } | Sort-Object -Unique)
    foreach ($name in $names) {
        if ($name) { netsh advfirewall firewall delete rule name="$name" 2>&1 | Out-Null }
    }

    $list = @($allIps)
    $batchCount = 0
    for ($i = 0; $i -lt $list.Count; $i += $BatchSize) {
        $take = [Math]::Min($BatchSize, $list.Count - $i)
        $batch = $list[$i..($i + $take - 1)]
        $batchCount++
        $ruleName = $DisplayNamePrefix + $batchCount
        $addrs = $batch -join ","
        try {
            netsh advfirewall firewall add rule name="$ruleName" dir=out action=block remoteip=$addrs enabled=yes 2>&1 | Out-Null
            Write-GRulesLog "Created $ruleName for $($batch.Count) IP(s)"
        } catch {
            Write-GRulesLog "Failed $ruleName : $_"
        }
    }
}

if (-not $script:EmbeddedGRulesC2Block) { Invoke-GRulesC2Block }
