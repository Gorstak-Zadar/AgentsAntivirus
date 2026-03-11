# ProcessAuditing.ps1 - GEDR-aligned: enable Process Creation auditing so Security log records 4688 events

#Requires -RunAsAdministrator

function Invoke-ProcessAuditing {
    $audit = auditpol /get /subcategory:"Process Creation" /r 2>&1 | Out-String
    if ($audit -match 'Process Creation\s+(\w+)\s+(\w+)') {
        $s = $Matches[1]; $f = $Matches[2]
        if ($s -eq 'Enable' -and $f -eq 'Enable') {
            Write-Host "Process Creation auditing is already enabled."
            return
        }
    }
    $result = auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Process Creation auditing enabled. Security log will record 4688 events."
    } else {
        Write-Warning "Failed to enable Process Creation auditing: $result"
    }
}

if (-not $script:EmbeddedProcessAuditing) { Invoke-ProcessAuditing }
