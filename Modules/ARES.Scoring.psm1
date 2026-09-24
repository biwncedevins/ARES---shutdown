#Requires -Version 5.1
<#
    ARES.Scoring.psm1
    ------------------
    Weighted behavioral correlation engine. A single low-confidence
    indicator never triggers containment on its own - scores are additive
    across independent indicator categories, and the resulting reasons list
    is preserved so the final report can explain *why* a score was reached.

    Weights are configuration-driven defaults; ARES.Policy can override
    them per deployment.
#>

Set-StrictMode -Version Latest

$Script:AresDefaultWeights = @{
    unsigned_executable        = 20
    invalid_signature          = 15
    temp_execution             = 15
    downloads_execution        = 10
    appdata_execution          = 10
    recently_created           = 10
    suspicious_filename        = 10
    unusual_parent_child       = 20
    office_or_browser_spawned_shell = 30
    powershell_launched_unsigned = 25
    script_interpreter_to_payload = 25
    suspicious_outbound        = 25
    beacon_like_pattern        = 20
    persistence_creation       = 30
    credential_access          = 30
    suspicious_handle_access   = 15
    unusual_dll_load           = 15
    injection_indicator        = 35
    abnormal_execution_path    = 10
}

$Script:AresLolBins = @(
    'powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe',
    'rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe','msiexec.exe',
    'reg.exe','schtasks.exe','sc.exe'
)

$Script:AresShellLaunchers = @('winword.exe','excel.exe','powerpnt.exe','outlook.exe',
    'chrome.exe','msedge.exe','firefox.exe','acrord32.exe','acrobat.exe')

function Get-AresIndicatorsForProcess {
    <#
        Derives indicator flags for a single process node from the
        inventory + ancestry + optional telemetry (network/persistence/cred
        events keyed by PID, supplied by the caller when available).
    #>
    param(
        [Parameter(Mandatory)]$Process,          # inventory entry
        [Parameter(Mandatory)][array]$Ancestry,   # root..process chain
        [hashtable]$NetworkIndicatorsByPid = @{},
        [hashtable]$PersistenceIndicatorsByPid = @{},
        [hashtable]$CredentialIndicatorsByPid = @{}
    )

    $indicators = @()
    $path = $Process.path
    $name = ($Process.name).ToLowerInvariant()

    if ($Process.signature_status -in @('NotSigned')) { $indicators += 'unsigned_executable' }
    elseif ($Process.signature_status -in @('HashMismatch','NotTrusted','UnknownError')) { $indicators += 'invalid_signature' }

    if ($path) {
        if ($path -match '(?i)\\Temp\\') { $indicators += 'temp_execution' }
        if ($path -match '(?i)\\Downloads\\') { $indicators += 'downloads_execution' }
        if ($path -match '(?i)\\AppData\\') { $indicators += 'appdata_execution' }
    }

    if ($path -and (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
        try {
            $age = (Get-Date) - (Get-Item -LiteralPath $path).CreationTime
            if ($age.TotalHours -lt 24) { $indicators += 'recently_created' }
        } catch { }
    }

    if ($name -match '(?i)(svch0st|scvhost|explorar|chr0me|update[0-9]+\.exe|invoice.*\.exe|\.pdf\.exe|\.doc\.exe)') {
        $indicators += 'suspicious_filename'
    }

    # Parent/child relationship checks against ancestry.
    if ($Ancestry.Count -ge 2) {
        $parent = $Ancestry[$Ancestry.Count - 2]
        $parentName = ($parent.name).ToLowerInvariant()

        if ($Script:AresShellLaunchers -contains $parentName -and $name -in @('cmd.exe','powershell.exe','pwsh.exe')) {
            $indicators += 'office_or_browser_spawned_shell'
        }
        if ($parentName -in @('powershell.exe','pwsh.exe') -and $Process.signature_status -eq 'NotSigned') {
            $indicators += 'powershell_launched_unsigned'
        }
        if (($Script:AresLolBins -contains $parentName) -and ($Script:AresLolBins -notcontains $name) -and $Process.signature_status -ne 'Valid') {
            $indicators += 'script_interpreter_to_payload'
        }
        if (($Script:AresLolBins -contains $name) -and $parentName -notin @('explorer.exe','services.exe','svchost.exe','cmd.exe','powershell.exe','pwsh.exe','taskeng.exe','taskhostw.exe')) {
            $indicators += 'unusual_parent_child'
        }
    }

    $netInd = $NetworkIndicatorsByPid[[int]$Process.pid_]
    if ($netInd) {
        if ($netInd.suspicious_outbound) { $indicators += 'suspicious_outbound' }
        if ($netInd.beacon_like) { $indicators += 'beacon_like_pattern' }
    }

    $persInd = $PersistenceIndicatorsByPid[[int]$Process.pid_]
    if ($persInd -and $persInd.created_persistence) { $indicators += 'persistence_creation' }

    $credInd = $CredentialIndicatorsByPid[[int]$Process.pid_]
    if ($credInd -and $credInd.accessed_credential_store) { $indicators += 'credential_access' }

    return $indicators
}

function Get-AresBehavioralScore {
    <#
        Combines indicators into a numeric score, a severity band, and a
        human-readable reasons breakdown for the report.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Indicators,
        [hashtable]$Weights = $Script:AresDefaultWeights
    )

    $total = 0
    $reasons = @()
    foreach ($ind in ($Indicators | Select-Object -Unique)) {
        $w = $Weights[$ind]
        if (-not $w) { $w = 5 }
        $total += $w
        $reasons += "+$w $ind"
    }

    $severity =
        if ($total -ge 90) { 'CRITICAL' }
        elseif ($total -ge 55) { 'HIGH' }
        elseif ($total -ge 25) { 'MEDIUM' }
        elseif ($total -gt 0) { 'LOW' }
        else { 'NONE' }

    return [PSCustomObject]@{
        score    = $total
        severity = $severity
        reasons  = $reasons
        indicators = $Indicators | Select-Object -Unique
    }
}

Export-ModuleMember -Function Get-AresIndicatorsForProcess, Get-AresBehavioralScore
Export-ModuleMember -Variable AresDefaultWeights, AresLolBins
