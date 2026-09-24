#Requires -Version 5.1
<#
    ARES.Policy.psm1
    ------------------
    Centralized policy engine. Every containment/quarantine/recovery
    threshold decision is read from here rather than scattered through
    the codebase.
#>

Set-StrictMode -Version Latest

function Get-AresPolicy {
    <#
        Returns a policy object for the requested emergency profile.
        Profiles: STANDARD | AGGRESSIVE | FORENSIC | LOCKDOWN
        Individual fields may be overridden via -Overrides.
    #>
    param(
        [ValidateSet('STANDARD','AGGRESSIVE','FORENSIC','LOCKDOWN')]
        [string]$Profile = 'STANDARD',
        [hashtable]$Overrides = @{},
        [string[]]$AllowedExceptionPrograms = @(
            "$env:windir\System32\svchost.exe",
            "$env:windir\System32\lsass.exe"
        )
    )

    $base = switch ($Profile) {
        'STANDARD' {
            @{
                network_policy               = 'isolate-all'
                process_termination_threshold = 'HIGH'   # score band that triggers termination
                quarantine_threshold          = 'MEDIUM'
                credential_telemetry_enabled  = $true
                memory_acquisition_enabled    = $false
                persistence_auto_disable      = $false   # capture + record only, operator confirms disable
                allow_critical_process_override = $false
                logging_max_mb                = 500
            }
        }
        'AGGRESSIVE' {
            @{
                network_policy               = 'isolate-all'
                process_termination_threshold = 'MEDIUM'
                quarantine_threshold          = 'MEDIUM'
                credential_telemetry_enabled  = $true
                memory_acquisition_enabled    = $true
                persistence_auto_disable      = $true
                allow_critical_process_override = $false
                logging_max_mb                = 750
            }
        }
        'FORENSIC' {
            @{
                network_policy               = 'suspicious-only'
                process_termination_threshold = 'CRITICAL'  # prefer evidence preservation over disruption
                quarantine_threshold          = 'HIGH'
                credential_telemetry_enabled  = $true
                memory_acquisition_enabled    = $true
                persistence_auto_disable      = $false
                allow_critical_process_override = $false
                logging_max_mb                = 2000
            }
        }
        'LOCKDOWN' {
            @{
                network_policy               = 'hard-disconnect'
                process_termination_threshold = 'MEDIUM'
                quarantine_threshold          = 'LOW'
                credential_telemetry_enabled  = $true
                memory_acquisition_enabled    = $true
                persistence_auto_disable      = $true
                allow_critical_process_override = $false  # still requires an EXPLICIT separate flag to ever touch critical list
                logging_max_mb                = 1000
            }
        }
    }

    $base['profile'] = $Profile
    $base['allowed_exception_programs'] = $AllowedExceptionPrograms

    foreach ($k in $Overrides.Keys) { $base[$k] = $Overrides[$k] }

    return [PSCustomObject]$base
}

function Get-AresSeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'CRITICAL' { return 4 }
        'HIGH'     { return 3 }
        'MEDIUM'   { return 2 }
        'LOW'      { return 1 }
        default    { return 0 }
    }
}

function Test-AresMeetsThreshold {
    param([string]$Severity, [string]$Threshold)
    return (Get-AresSeverityRank $Severity) -ge (Get-AresSeverityRank $Threshold)
}

Export-ModuleMember -Function Get-AresPolicy, Get-AresSeverityRank, Test-AresMeetsThreshold
