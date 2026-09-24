#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ARES - shutdown : Emergency Blue Team Endpoint Containment & Forensic Response.

.DESCRIPTION
    Run this immediately if you suspect you have just executed malware
    (RAT, stealer, dropper, etc.) on a Windows endpoint. It will:

      1. Initialize a tamper-evident forensic case
      2. Apply immediate network containment
      3. Enumerate the full process tree
      4. Score every process for suspicious behavior
      5. Contain (evidence-capture then terminate) high-confidence threats
      6. Inspect persistence mechanisms and quarantine suspicious files
      7. Build a unified incident timeline
      8. Produce an evidence bundle and final report

    ARES never GUIs. All meaningful output goes to the forensic log and the
    evidence bundle; the console only prints minimal status lines.

.PARAMETER Profile
    STANDARD | AGGRESSIVE | FORENSIC | LOCKDOWN  (default STANDARD)

.PARAMETER NetworkPolicy
    Override the profile's default network containment policy explicitly:
    suspicious-only | isolate-all | hard-disconnect

.PARAMETER EvidenceRoot
    Directory under which the case folder and zip are created.
    Default: C:\ProgramData\ARES-Shutdown\Cases

.EXAMPLE
    .\Start-ARES.ps1 -Profile AGGRESSIVE

.EXAMPLE
    .\Start-ARES.ps1 -Profile LOCKDOWN -NetworkPolicy hard-disconnect
#>

[CmdletBinding()]
param(
    [ValidateSet('STANDARD','AGGRESSIVE','FORENSIC','LOCKDOWN')]
    [string]$Profile = 'STANDARD',

    [ValidateSet('suspicious-only','isolate-all','hard-disconnect','')]
    [string]$NetworkPolicy = '',

    [string]$EvidenceRoot = 'C:\ProgramData\ARES-Shutdown\Cases',

    [switch]$SkipMemoryAcquisition
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$AresVersion = '1.0.0-stage1'
$ModuleDir = Join-Path $PSScriptRoot 'Modules'

Import-Module (Join-Path $ModuleDir 'ARES.Logging.psm1')      -Force
Import-Module (Join-Path $ModuleDir 'ARES.Network.psm1')      -Force
Import-Module (Join-Path $ModuleDir 'ARES.Process.psm1')      -Force
Import-Module (Join-Path $ModuleDir 'ARES.Scoring.psm1')      -Force
Import-Module (Join-Path $ModuleDir 'ARES.Persistence.psm1')  -Force
Import-Module (Join-Path $ModuleDir 'ARES.Quarantine.psm1')   -Force
Import-Module (Join-Path $ModuleDir 'ARES.Evidence.psm1')     -Force
Import-Module (Join-Path $ModuleDir 'ARES.Policy.psm1')       -Force

Write-Host "ARES - shutdown: emergency containment active" -ForegroundColor Red

# ---------------------------------------------------------------------------
# PHASE 0 - Secure Initialization
# ---------------------------------------------------------------------------
$caseId = New-AresCaseId
$exePath = $MyInvocation.MyCommand.Path
$exeHash = $null
try { $exeHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }

$case = Initialize-AresCase -CaseId $caseId -BaseEvidenceRoot $EvidenceRoot -AresVersion $AresVersion

$policy = Get-AresPolicy -Profile $Profile
if ($NetworkPolicy) { $policy.network_policy = $NetworkPolicy }
if ($SkipMemoryAcquisition) { $policy.memory_acquisition_enabled = $false }

Write-AresEvent -Case $case -EventType 'PHASE0_INIT' -Severity INFO -Result SUCCESS -Message 'Secure initialization complete' -Data @{
    hostname       = $env:COMPUTERNAME
    username       = "$env:USERDOMAIN\$env:USERNAME"
    os_version     = [System.Environment]::OSVersion.VersionString
    architecture   = $env:PROCESSOR_ARCHITECTURE
    ares_version   = $AresVersion
    ares_exe_hash  = $exeHash
    profile        = $Profile
    acl_result     = $case.AclResult
    eventlog_result = $case.EventLogResult
}

Write-Host "ARES - shutdown: case $caseId initialized (profile=$Profile)" -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# PHASE 1 - Immediate Network Containment
# ---------------------------------------------------------------------------
$netSnapshotBefore = Get-AresNetworkSnapshot -Case $case
$netContainment = Invoke-AresNetworkContainment -Case $case -Policy $policy.network_policy `
    -AllowedExceptionPrograms $policy.allowed_exception_programs

Write-Host "ARES - shutdown: network containment [$($netContainment.status)] policy=$($policy.network_policy)" -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# PHASE 2 - Process Enumeration + Tree
# ---------------------------------------------------------------------------
$inventory = Get-AresProcessInventory -Case $case
Write-Host "ARES - shutdown: enumerated $($inventory.Count) processes" -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# PHASE 3 - Persistence + Credential telemetry inputs (best-effort, feeds scoring)
# ---------------------------------------------------------------------------
$persistenceFindings = Get-AresPersistenceFindings -Case $case

# NOTE: Full ETW-based credential-access telemetry (LSASS handle access,
# browser credential-store file opens, etc.) is a Stage 2/3 capability per
# the implementation strategy and requires either Sysmon or a signed
# ETW-consuming component. This Stage 1 build initializes the structure and
# records NOT_AVAILABLE rather than fabricating detections.
$credentialIndicatorsByPid = @{}
Write-AresEvent -Case $case -EventType 'CREDENTIAL_TELEMETRY_STAGE' -Severity INFO -Result 'NOT_AVAILABLE' `
    -Message 'ETW-based credential access telemetry requires Stage 2/3 component; not active in this build.'

$networkIndicatorsByPid = @{}
foreach ($conn in $netSnapshotBefore.tcp) {
    if (-not $conn.OwningProcess) { continue }
    $remote = $conn.RemoteAddress
    if ($remote -and $remote -notmatch '^(127\.|0\.0\.0\.0|::1|::)' -and $conn.State -eq 'Established') {
        if (-not $networkIndicatorsByPid.ContainsKey([int]$conn.OwningProcess)) {
            $networkIndicatorsByPid[[int]$conn.OwningProcess] = @{ suspicious_outbound = $false; beacon_like = $false }
        }
    }
}

$persistenceIndicatorsByPid = @{}  # Stage 1: persistence-to-process attribution requires ETW; left NOT_AVAILABLE.

# ---------------------------------------------------------------------------
# PHASE 4 - Behavioral Scoring
# ---------------------------------------------------------------------------
$scoredProcesses = @()
foreach ($proc in $inventory) {
    $ancestry = Get-AresProcessAncestry -Inventory $inventory -ProcessId $proc.pid_
    $indicators = Get-AresIndicatorsForProcess -Process $proc -Ancestry $ancestry `
        -NetworkIndicatorsByPid $networkIndicatorsByPid `
        -PersistenceIndicatorsByPid $persistenceIndicatorsByPid `
        -CredentialIndicatorsByPid $credentialIndicatorsByPid
    $score = Get-AresBehavioralScore -Indicators $indicators

    if ($score.severity -ne 'NONE') {
        Write-AresEvent -Case $case -EventType 'PROCESS_SCORED' -Severity $score.severity -Result SUCCESS `
            -Message "$($proc.name) (PID $($proc.pid_)) scored $($score.score)" `
            -Data @{ pid = $proc.pid_; name = $proc.name; score = $score.score; reasons = $score.reasons }
    }

    $scoredProcesses += [PSCustomObject]@{
        pid_       = $proc.pid_
        name       = $proc.name
        path       = $proc.path
        score      = $score.score
        severity   = $score.severity
        reasons    = $score.reasons
        indicators = $score.indicators
    }
}

$actionableProcesses = $scoredProcesses | Where-Object {
    Test-AresMeetsThreshold -Severity $_.severity -Threshold $policy.process_termination_threshold
}

Write-Host "ARES - shutdown: $($actionableProcesses.Count) process(es) meet containment threshold ($($policy.process_termination_threshold)+)" -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# PHASE 5 - Process Containment (leaves -> root, evidence captured first)
# ---------------------------------------------------------------------------
$terminationResults = @()
foreach ($sp in $actionableProcesses) {
    $reasonText = ($sp.reasons -join '; ')
    $results = Stop-AresProcessTree -Case $case -Inventory $inventory -RootProcessId $sp.pid_ `
        -Reason "score=$($sp.score) severity=$($sp.severity) [$reasonText]" `
        -AllowCriticalOverride:($policy.allow_critical_process_override -and $Profile -eq 'LOCKDOWN')
    $terminationResults += $results
}

# ---------------------------------------------------------------------------
# PHASE 6 - Quarantine suspicious files tied to actionable processes
# ---------------------------------------------------------------------------
$quarantineResults = @()
foreach ($sp in $actionableProcesses) {
    if (Test-AresMeetsThreshold -Severity $sp.severity -Threshold $policy.quarantine_threshold) {
        if ($sp.path) {
            $qr = Move-AresFileToQuarantine -Case $case -FilePath $sp.path -Reason "process score=$($sp.score) [$($sp.reasons -join '; ')]"
            $quarantineResults += $qr
        }
    }
}

# ---------------------------------------------------------------------------
# PHASE 7 - Persistence disable (policy-gated; STANDARD/FORENSIC capture-only)
# ---------------------------------------------------------------------------
$persistenceActions = @()
if ($policy.persistence_auto_disable) {
    foreach ($f in $persistenceFindings) {
        if ($f.type -eq 'RunKey' -and $f.risk_hint -eq 'high-review') {
            $r = Disable-AresRunKeyEntry -Case $case -KeyPath $f.location -ValueName $f.name -Reason 'auto-disable policy (high-risk hint)'
            $persistenceActions += $r
        }
    }
} else {
    Write-AresEvent -Case $case -EventType 'PERSISTENCE_AUTO_DISABLE_SKIPPED' -Severity INFO -Result 'NOT_AVAILABLE' `
        -Message "Profile $Profile captures persistence findings but does not auto-disable; review persistence.json and disable manually if warranted."
}

# ---------------------------------------------------------------------------
# PHASE 8 - Timeline + Evidence Bundle + Final Report
# ---------------------------------------------------------------------------
$timeline = Build-AresTimeline -Case $case

$containmentStatus =
    if ($netContainment.status -eq 'SUCCESS') { 'CONTAINED' }
    elseif ($netContainment.status -eq 'PARTIAL') { 'PARTIALLY_CONTAINED' }
    else { 'CONTAINMENT_DEGRADED' }

$attackBehavior = @()
if ($actionableProcesses.Count -gt 0) {
    $attackBehavior += [PSCustomObject]@{ confidence = 'Observed'; description = "$($actionableProcesses.Count) process(es) exceeded the $($policy.process_termination_threshold) behavioral threshold." }
} else {
    $attackBehavior += [PSCustomObject]@{ confidence = 'Observed'; description = 'No process exceeded the configured containment threshold during this scan.' }
}
if ($persistenceFindings.Count -gt 0) {
    $attackBehavior += [PSCustomObject]@{ confidence = 'Suspected'; description = "$($persistenceFindings.Count) persistence-mechanism entries present; not all reviewed against a known-good baseline." }
}
$attackBehavior += [PSCustomObject]@{ confidence = 'Unknown'; description = 'Credential-access telemetry (LSASS / browser store access) requires the Stage 2/3 ETW component and was not available in this run.' }

$incidentSummary = [PSCustomObject]@{
    case_id                        = $case.CaseId
    start_time_utc                 = $case.StartTimeUtc.ToString('o')
    containment_status             = $containmentStatus
    suspicious_process_count       = ($scoredProcesses | Where-Object { $_.severity -ne 'NONE' }).Count
    terminated_process_count       = ($terminationResults | Where-Object { $_.status -eq 'TERMINATED' }).Count
    blocked_connection_count       = $netContainment.rules_created.Count
    persistence_finding_count      = $persistenceFindings.Count
    credential_access_event_count  = 0
    suspicious_file_count          = $actionableProcesses.Count
    quarantined_file_count         = ($quarantineResults | Where-Object { $_.status -eq 'SUCCESS' }).Count
    initial_execution_chain        = $(if ($actionableProcesses.Count -gt 0) {
                                            $top = $actionableProcesses | Sort-Object score -Descending | Select-Object -First 1
                                            $chain = Get-AresProcessAncestry -Inventory $inventory -ProcessId $top.pid_
                                            ($chain | ForEach-Object { $_.name }) -join ' -> '
                                        } else { 'No high-confidence execution chain identified in this scan.' })
    attack_behavior                = $attackBehavior
    evidence_bundle_path           = '(set after bundling)'
    recovery_status                = 'NOT_ATTEMPTED - operator-initiated only, see ARES.Network/Persistence/Quarantine recovery functions'
    containment_confidence         = $containmentStatus
    root_cause_hypothesis          = $(if ($actionableProcesses.Count -gt 0) {
                                            "Suspected initial execution of $($($actionableProcesses | Sort-Object score -Descending | Select-Object -First 1).name); confirm via user interview and the process/timeline evidence."
                                        } else { 'Unknown - no process met the containment threshold; review timeline.txt and process_tree.json manually.' })
    highest_confidence_indicators  = ($actionableProcesses | Sort-Object score -Descending | Select-Object -First 5 | ForEach-Object { "$($_.name) (PID $($_.pid_)) score=$($_.score): $($_.reasons -join ', ')" })
    unresolved_questions           = @(
        'Was this the first execution of the suspicious binary, or a re-execution?'
        'What was the delivery vector (email attachment, download, USB, etc.)?'
        'Did any data leave the network before containment was applied?'
    )
    containment_limitations        = @(
        'User-mode process monitoring is detection/response, not an absolute security boundary.'
        'Credential-access telemetry was not available in this build (requires Stage 2/3 ETW component).'
        'Persistence-to-originating-process attribution requires ETW and was not available in this run.'
        $(if (-not $policy.memory_acquisition_enabled) { 'Memory acquisition was disabled for this profile/run.' })
    ) | Where-Object { $_ }
    recommended_next_actions       = @(
        'Review process_tree.json and timeline.txt for the full ancestry of any HIGH/CRITICAL process.'
        'Submit quarantined file hashes to a malware analysis pipeline before considering restoration.'
        'Rotate credentials for any account active on this endpoint since the estimated compromise window.'
        'If network egress occurred, coordinate with network/security team to review upstream logs.'
    )
}

$configForBundle = @{
    profile                 = $Profile
    network_policy           = $policy.network_policy
    process_termination_threshold = $policy.process_termination_threshold
    quarantine_threshold     = $policy.quarantine_threshold
    persistence_auto_disable = $policy.persistence_auto_disable
    memory_acquisition_enabled = $policy.memory_acquisition_enabled
}

$bundleResult = New-AresEvidenceBundle -Case $case -Configuration $configForBundle -IncidentSummary $incidentSummary
$incidentSummary.evidence_bundle_path = $bundleResult.path

$logIntegrity = Test-AresLogChainIntegrity -Case $case
Write-AresEvent -Case $case -EventType 'LOG_CHAIN_INTEGRITY_CHECK' -Severity INFO `
    -Result $(if ($logIntegrity.Valid) { 'SUCCESS' } else { 'FAILED' }) -Data @{ valid = $logIntegrity.Valid; checked = $logIntegrity.Checked }

$reportPath = New-AresFinalReport -Case $case -IncidentSummary $incidentSummary

Write-Host "ARES - shutdown: containment cycle complete. Status=$containmentStatus" -ForegroundColor Red
Write-Host "ARES - shutdown: case folder   -> $($case.CaseRoot)" -ForegroundColor Yellow
Write-Host "ARES - shutdown: evidence zip  -> $($bundleResult.path) [$($bundleResult.status)]" -ForegroundColor Yellow
Write-Host "ARES - shutdown: final report  -> $reportPath" -ForegroundColor Yellow

return $incidentSummary
