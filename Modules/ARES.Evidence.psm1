#Requires -Version 5.1
<#
    ARES.Evidence.psm1
    ---------------------
    Builds the incident timeline, the final evidence bundle (ARES_CASE_<id>.zip),
    the manifest with hashes, and the human-readable final incident report.
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'ARES.Logging.psm1') -Force

function Build-AresTimeline {
    <#
        Reconstructs a unified chronological timeline from the JSONL
        forensic log. This is a first-class evidence artifact, not just a
        debug convenience.
    #>
    param([Parameter(Mandatory)]$Case)

    $timeline = @()
    if (Test-Path $Case.JsonlPath) {
        Get-Content -Path $Case.JsonlPath -Encoding UTF8 | ForEach-Object {
            $e = $_ | ConvertFrom-Json
            $timeline += [PSCustomObject]@{
                timestamp_utc = $e.timestamp_utc
                event_type    = $e.event_type
                severity      = $e.severity
                result        = $e.result
                message       = $e.message
            }
        }
    }
    $timeline = $timeline | Sort-Object timestamp_utc

    $jsonPath = Join-Path $Case.EvidenceDir 'timeline.json'
    $txtPath  = Join-Path $Case.EvidenceDir 'timeline.txt'

    try { ($timeline | ConvertTo-Json -Depth 6) | Set-Content -Path $jsonPath -Encoding UTF8 } catch { }
    try {
        $lines = $timeline | ForEach-Object {
            $shortTime = ([datetime]$_.timestamp_utc).ToString('HH:mm:ss')
            "$shortTime  [$($_.severity)] $($_.event_type) - $($_.message) ($($_.result))"
        }
        $lines | Set-Content -Path $txtPath -Encoding UTF8
    } catch { }

    Write-AresEvent -Case $Case -EventType 'TIMELINE_BUILT' -Severity INFO -Result SUCCESS -Message "$($timeline.Count) events"
    return $timeline
}

function New-AresEvidenceBundle {
    <#
        Zips the entire case evidence directory (logs + evidence + quarantine
        metadata + configuration) into ARES_CASE_<CaseId>.zip and computes a
        manifest of SHA-256 hashes for every included file.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][hashtable]$Configuration,
        [Parameter(Mandatory)][PSCustomObject]$IncidentSummary
    )

    $incidentPath = Join-Path $Case.EvidenceDir 'incident.json'
    ($IncidentSummary | ConvertTo-Json -Depth 12) | Set-Content -Path $incidentPath -Encoding UTF8

    $configPath = Join-Path $Case.EvidenceDir 'configuration.json'
    ($Configuration | ConvertTo-Json -Depth 8) | Set-Content -Path $configPath -Encoding UTF8

    # Manifest: hash every file under the case root except the zip itself.
    $manifest = @()
    $allFiles = Get-ChildItem -Path $Case.CaseRoot -Recurse -File -ErrorAction SilentlyContinue
    foreach ($f in $allFiles) {
        try {
            $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            $manifest += [PSCustomObject]@{ path = $f.FullName.Substring($Case.CaseRoot.Length + 1); sha256 = $h; size = $f.Length }
        } catch { }
    }
    $manifestPath = Join-Path $Case.EvidenceDir 'manifest.json'
    ($manifest | ConvertTo-Json -Depth 6) | Set-Content -Path $manifestPath -Encoding UTF8

    $zipPath = Join-Path (Split-Path $Case.CaseRoot -Parent) "ARES_CASE_$($Case.CaseId).zip"
    $status = 'FAILED'
    try {
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path (Join-Path $Case.CaseRoot '*') -DestinationPath $zipPath -CompressionLevel Optimal -ErrorAction Stop
        $status = 'SUCCESS'
    } catch {
        $status = 'FAILED'
    }

    Write-AresEvent -Case $Case -EventType 'EVIDENCE_BUNDLE_CREATED' -Severity INFO -Result $status -Message $zipPath

    return [PSCustomObject]@{ status = $status; path = $zipPath; manifest_count = $manifest.Count }
}

function New-AresFinalReport {
    <#
        Produces the human-readable final incident report per spec section 34.
        Explicitly distinguishes Observed / Inferred / Suspected / Unknown and
        never overstates certainty.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][PSCustomObject]$IncidentSummary
    )

    $s = $IncidentSummary
    $lines = @()
    $lines += "================================================================"
    $lines += "ARES - shutdown : FINAL INCIDENT REPORT"
    $lines += "================================================================"
    $lines += "CASE ID:                 $($Case.CaseId)"
    $lines += "START TIME (UTC):        $($Case.StartTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    $lines += "CONTAINMENT STATUS:      $($s.containment_status)"
    $lines += ""
    $lines += "SUSPICIOUS PROCESSES:    $($s.suspicious_process_count)"
    $lines += "TERMINATED PROCESSES:    $($s.terminated_process_count)"
    $lines += "NETWORK CONNECTIONS BLOCKED: $($s.blocked_connection_count)"
    $lines += "PERSISTENCE MECHANISMS:  $($s.persistence_finding_count)"
    $lines += "CREDENTIAL ACCESS EVENTS: $($s.credential_access_event_count)"
    $lines += "SUSPICIOUS FILES:        $($s.suspicious_file_count)"
    $lines += "QUARANTINED FILES:       $($s.quarantined_file_count)"
    $lines += ""
    $lines += "INITIAL EXECUTION CHAIN:"
    $lines += "  $($s.initial_execution_chain)"
    $lines += ""
    $lines += "ATTACK BEHAVIOR (Observed / Inferred / Suspected / Unknown):"
    foreach ($b in $s.attack_behavior) { $lines += "  [$($b.confidence)] $($b.description)" }
    $lines += ""
    $lines += "EVIDENCE LOCATION:       $($s.evidence_bundle_path)"
    $lines += "RECOVERY STATUS:         $($s.recovery_status)"
    $lines += "CONTAINMENT CONFIDENCE:  $($s.containment_confidence)"
    $lines += ""
    $lines += "ROOT-CAUSE HYPOTHESIS:   $($s.root_cause_hypothesis)"
    $lines += ""
    $lines += "HIGHEST-CONFIDENCE INDICATORS:"
    foreach ($i in $s.highest_confidence_indicators) { $lines += "  - $i" }
    $lines += ""
    $lines += "UNRESOLVED QUESTIONS:"
    foreach ($q in $s.unresolved_questions) { $lines += "  - $q" }
    $lines += ""
    $lines += "CONTAINMENT LIMITATIONS:"
    foreach ($l in $s.containment_limitations) { $lines += "  - $l" }
    $lines += ""
    $lines += "RECOMMENDED NEXT FORENSIC ACTIONS:"
    foreach ($a in $s.recommended_next_actions) { $lines += "  - $a" }
    $lines += "================================================================"

    $reportPath = Join-Path $Case.EvidenceDir 'final_report.txt'
    $lines | Set-Content -Path $reportPath -Encoding UTF8

    Write-AresEvent -Case $Case -EventType 'FINAL_REPORT_GENERATED' -Severity INFO -Result SUCCESS -Message $reportPath
    return $reportPath
}

Export-ModuleMember -Function Build-AresTimeline, New-AresEvidenceBundle, New-AresFinalReport
