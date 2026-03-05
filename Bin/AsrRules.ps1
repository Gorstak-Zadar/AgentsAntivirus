# AsrRules.ps1 - GEDR-aligned: apply Windows Defender ASR rules (same GUIDs as GEDR EdrAsrRules)

#Requires -RunAsAdministrator

function Invoke-AsrRules {
    $AsrRuleIds = @(
        "56a863a9-875e-4185-98a7-b882c64b5ce5"  # block_office_child_process
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc"  # block_script_execution
        "e6db77e5-3df2-4cf1-b95a-636979351e5b"  # block_executable_email
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a"  # block_office_macros
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"  # block_usb_execution
    )
    foreach ($id in $AsrRuleIds) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Write-Host "Applied ASR rule: $id"
        } catch {
            Write-Warning "ASR rule $id : $_"
        }
    }
    Write-Host "ASR rules applied."
}

if (-not $script:EmbeddedAsrRules) { Invoke-AsrRules }
