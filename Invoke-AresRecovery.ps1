#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ARES - shutdown : Controlled recovery for a completed case.

.DESCRIPTION
    Recovery is ALWAYS explicit and operator-initiated. ARES never restores
    suspicious content automatically just because it exits. This script:

      - Removes the case's firewall containment rules (and re-enables any
        adapters disabled under hard-disconnect)
      - Optionally restores specific quarantined files by transaction/path
      - Prints a summary of what was reversed vs. what remains quarantined

    It does NOT re-enable disabled persistence entries automatically -
    review persistence.json first and re-enable specific entries deliberately
    if you're confident they are benign.

.PARAMETER CaseId
    The Case ID to recover (matches the folder name under EvidenceRoot).

.PARAMETER RestoreQuarantinedFile
    Optional path(s) to specific quarantined files (under the case's
    quarantine folder) to restore to their original location.

.EXAMPLE
    .\Invoke-AresRecovery.ps1 -CaseId ARES-20260816T101112Z-9F3A21B0 -RemoveNetworkContainment

.EXAMPLE
    .\Invoke-AresRecovery.ps1 -CaseId ARES-20260816T101112Z-9F3A21B0 `
        -RestoreQuarantinedFile 'C:\ProgramData\ARES-Shutdown\Cases\ARES-...\quarantine\ab12....quarantined'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CaseId,
    [string]$EvidenceRoot = 'C:\ProgramData\ARES-Shutdown\Cases',
    [switch]$RemoveNetworkContainment,
    [string[]]$RestoreQuarantinedFile = @(),
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$ModuleDir = Join-Path $PSScriptRoot 'Modules'
Import-Module (Join-Path $ModuleDir 'ARES.Logging.psm1')    -Force
Import-Module (Join-Path $ModuleDir 'ARES.Network.psm1')    -Force
Import-Module (Join-Path $ModuleDir 'ARES.Quarantine.psm1') -Force

$caseRoot = Join-Path $EvidenceRoot $CaseId
if (-not (Test-Path $caseRoot)) {
    Write-Host "ARES - shutdown: case $CaseId not found under $EvidenceRoot" -ForegroundColor Red
    exit 1
}

# Reconstruct a minimal $case context object pointing at the existing case.
$case = [PSCustomObject]@{
    CaseId          = $CaseId
    CaseRoot        = $caseRoot
    LogsDir         = Join-Path $caseRoot 'logs'
    QuarantineDir   = Join-Path $caseRoot 'quarantine'
    EvidenceDir     = Join-Path $caseRoot 'evidence'
    MemoryDir       = Join-Path $caseRoot 'memory'
    JsonlPath       = Join-Path (Join-Path $caseRoot 'logs') 'ares.jsonl'
    TransactionPath = Join-Path (Join-Path $caseRoot 'logs') 'transactions.jsonl'
    LastEventHash   = ('0' * 64)
    EventCounter    = 0
    AclResult       = 'N/A'
    EventLogResult  = 'N/A'
}
# Resume the hash chain from the last recorded event, if present.
if (Test-Path $case.JsonlPath) {
    $last = Get-Content -Path $case.JsonlPath -Encoding UTF8 -Tail 1 | ConvertFrom-Json
    if ($last) {
        $case.LastEventHash = $last.current_event_hash
        $case.EventCounter = $last.sequence
    }
}

Write-Host "ARES - shutdown: RECOVERY mode for case $CaseId" -ForegroundColor Yellow

if ($RemoveNetworkContainment) {
    $r = Remove-AresNetworkContainment -Case $case
    Write-Host "  Network containment removed: rules_removed=$($r.rules_removed) adapters_restored=$($r.adapters_restored) errors=$($r.errors.Count)" -ForegroundColor Yellow
}

foreach ($qf in $RestoreQuarantinedFile) {
    $r = Restore-AresQuarantinedFile -Case $case -QuarantinePath $qf -Force:$Force
    Write-Host "  Restore $qf -> $($r.status)" -ForegroundColor Yellow
}

Write-Host "ARES - shutdown: recovery actions logged to $($case.JsonlPath)" -ForegroundColor Yellow
Write-Host "ARES - shutdown: persistence entries were NOT auto-restored - review $($case.EvidenceDir)\persistence.json manually." -ForegroundColor Red
