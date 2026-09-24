#Requires -Version 5.1
<#
    ARES.Logging.psm1
    -----------------
    Secure, tamper-evident forensic logging for ARES - shutdown.

    Responsibilities:
      - Generate a unique Case ID
      - Maintain a hash-chained JSONL forensic log (tamper-EVIDENT, not immutable)
      - Mirror critical events into a dedicated Windows Event Log source
      - Maintain a separate transaction ledger for every reversible system change
      - Apply restrictive ACLs to the case evidence directory

    NOTE ON TAMPER EVIDENCE:
    The hash chain lets an investigator detect that a log was edited or
    truncated after the fact. It is NOT cryptographic immutability - a
    local administrator (or the malware, if it gains SYSTEM) could still
    rewrite the entire chain. Treat this as tamper-EVIDENT, not tamper-PROOF,
    and copy the evidence bundle off-box as soon as practical.
#>

Set-StrictMode -Version Latest

$Script:AresEventSource = 'ARES-Shutdown'
$Script:AresEventLogName = 'ARES-Shutdown'

function New-AresCaseId {
    <#
        Format: ARES-YYYYMMDDThhmmssZ-XXXXXXXX
        Sortable, unique, and self-describing.
    #>
    $ts = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $rand = -join ((1..8) | ForEach-Object { '{0:X}' -f (Get-Random -Maximum 16) })
    return "ARES-$ts-$rand"
}

function Initialize-AresCase {
    <#
        Creates the case directory structure and returns a $Case context
        object that every other module receives.
    #>
    param(
        [Parameter(Mandatory)][string]$CaseId,
        [Parameter(Mandatory)][string]$BaseEvidenceRoot,
        [Parameter(Mandatory)][string]$AresVersion
    )

    $caseRoot = Join-Path $BaseEvidenceRoot $CaseId
    $dirs = @(
        $caseRoot,
        (Join-Path $caseRoot 'logs'),
        (Join-Path $caseRoot 'quarantine'),
        (Join-Path $caseRoot 'evidence'),
        (Join-Path $caseRoot 'memory')
    )
    foreach ($d in $dirs) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }

    # Restrict ACLs: SYSTEM + Administrators only. Best-effort; report failure,
    # never claim success falsely.
    $aclResult = 'NOT_AVAILABLE'
    try {
        $acl = Get-Acl -Path $caseRoot
        $acl.SetAccessRuleProtection($true, $false) # disable inheritance, remove inherited
        $rules = @(
            (New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')),
            (New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        )
        foreach ($r in $rules) { $acl.AddAccessRule($r) }
        Set-Acl -Path $caseRoot -AclObject $acl
        $aclResult = 'SUCCESS'
    } catch {
        $aclResult = 'FAILED'
    }

    # Register the Windows Event Log source (best-effort, requires admin).
    $eventLogResult = 'NOT_AVAILABLE'
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Script:AresEventSource)) {
            New-EventLog -LogName $Script:AresEventLogName -Source $Script:AresEventSource -ErrorAction Stop
        }
        $eventLogResult = 'SUCCESS'
    } catch {
        $eventLogResult = 'FAILED'
    }

    $case = [PSCustomObject]@{
        CaseId          = $CaseId
        CaseRoot        = $caseRoot
        LogsDir         = Join-Path $caseRoot 'logs'
        QuarantineDir   = Join-Path $caseRoot 'quarantine'
        EvidenceDir     = Join-Path $caseRoot 'evidence'
        MemoryDir       = Join-Path $caseRoot 'memory'
        JsonlPath       = Join-Path (Join-Path $caseRoot 'logs') 'ares.jsonl'
        TransactionPath = Join-Path (Join-Path $caseRoot 'logs') 'transactions.jsonl'
        AresVersion     = $AresVersion
        StartTimeUtc    = (Get-Date).ToUniversalTime()
        LastEventHash   = ('0' * 64)   # genesis hash
        EventCounter    = 0
        AclResult       = $aclResult
        EventLogResult  = $eventLogResult
    }

    return $case
}

function Get-AresCanonicalJson {
    param([Parameter(Mandatory)]$Object)
    # Deterministic-ish canonicalization: PowerShell's ConvertTo-Json preserves
    # key insertion order, so as long as callers build ordered hashtables the
    # representation is stable across runs. Depth kept generous for nested evidence.
    return ($Object | ConvertTo-Json -Depth 12 -Compress)
}

function Write-AresEvent {
    <#
        Appends one tamper-evident event to the JSONL forensic log.
        Every event is also mirrored to the console (minimal) and, for
        MEDIUM+ severity, to the Windows Event Log.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$EventType,
        [Parameter(Mandatory)][ValidateSet('INFO','LOW','MEDIUM','HIGH','CRITICAL')]
        [string]$Severity,
        [string]$Message = '',
        [hashtable]$Data = @{},
        [string]$Result = 'SUCCESS'  # SUCCESS | PARTIAL | FAILED | NOT_AVAILABLE
    )

    $Case.EventCounter++
    $nowUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')

    $eventBody = [ordered]@{
        event_id           = [guid]::NewGuid().ToString()
        sequence           = $Case.EventCounter
        case_id            = $Case.CaseId
        timestamp_utc      = $nowUtc
        event_type         = $EventType
        severity           = $Severity
        result             = $Result
        message            = $Message
        data               = $Data
        previous_event_hash = $Case.LastEventHash
    }

    $canonical = Get-AresCanonicalJson -Object $eventBody
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytesToHash = [System.Text.Encoding]::UTF8.GetBytes($Case.LastEventHash + $canonical)
    $hashBytes = $sha.ComputeHash($bytesToHash)
    $currentHash = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })

    $eventBody['current_event_hash'] = $currentHash
    $finalLine = ($eventBody | ConvertTo-Json -Depth 12 -Compress)

    try {
        Add-Content -Path $Case.JsonlPath -Value $finalLine -Encoding UTF8
    } catch {
        Write-Host "ARES - shutdown: [LOG WRITE FAILED] $EventType" -ForegroundColor Red
    }

    $Case.LastEventHash = $currentHash

    if ($Severity -in @('MEDIUM','HIGH','CRITICAL') -and $Case.EventLogResult -eq 'SUCCESS') {
        try {
            $entryType = switch ($Severity) {
                'CRITICAL' { 'Error' }
                'HIGH'     { 'Warning' }
                default    { 'Information' }
            }
            Write-EventLog -LogName $Script:AresEventLogName -Source $Script:AresEventSource `
                -EntryType $entryType -EventId 1000 -Message "$EventType : $Message" -ErrorAction Stop
        } catch {
            # Non-fatal - the JSONL log remains authoritative.
        }
    }

    return $eventBody
}

function Write-AresTransaction {
    <#
        Records a reversible system-modifying action. Separate ledger from
        the general event log so the recovery engine can iterate it directly.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [string]$OriginalState = $null,
        [string]$NewState = $null,
        [bool]$Reversible = $true,
        [string]$Result = 'SUCCESS'
    )

    $txn = [ordered]@{
        transaction_id  = [guid]::NewGuid().ToString()
        case_id         = $Case.CaseId
        action          = $Action
        target          = $Target
        original_state  = $OriginalState
        new_state       = $NewState
        reversible      = $Reversible
        result          = $Result
        timestamp_utc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    }

    try {
        Add-Content -Path $Case.TransactionPath -Value ($txn | ConvertTo-Json -Depth 8 -Compress) -Encoding UTF8
    } catch {
        Write-AresEvent -Case $Case -EventType 'TRANSACTION_LOG_WRITE_FAILED' -Severity HIGH `
            -Message "Failed to write transaction record for $Action on $Target" -Result FAILED
    }

    Write-AresEvent -Case $Case -EventType 'TRANSACTION_RECORDED' -Severity INFO `
        -Message "$Action on $Target" -Data @{ transaction_id = $txn.transaction_id; reversible = $Reversible } -Result $Result

    return $txn
}

function Get-AresTransactions {
    param([Parameter(Mandatory)]$Case)
    if (-not (Test-Path $Case.TransactionPath)) { return @() }
    return Get-Content -Path $Case.TransactionPath -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json }
}

function Test-AresLogChainIntegrity {
    <#
        Walks the JSONL log and verifies every current_event_hash matches
        the recomputed hash of (previous_event_hash + canonical body).
        Returns a report object; does not throw on mismatch.
    #>
    param([Parameter(Mandatory)]$Case)

    if (-not (Test-Path $Case.JsonlPath)) {
        return [PSCustomObject]@{ Valid = $true; Checked = 0; FirstBreakSequence = $null }
    }

    $prevHash = ('0' * 64)
    $seq = 0
    $lines = Get-Content -Path $Case.JsonlPath -Encoding UTF8
    foreach ($line in $lines) {
        $seq++
        $obj = $line | ConvertFrom-Json
        $claimedCurrent = $obj.current_event_hash
        $claimedPrev = $obj.previous_event_hash
        if ($claimedPrev -ne $prevHash) {
            return [PSCustomObject]@{ Valid = $false; Checked = $seq; FirstBreakSequence = $seq; Reason = 'previous_hash_mismatch' }
        }
        # Recompute
        $copy = $obj | Select-Object * -ExcludeProperty current_event_hash
        $canonical = ($copy | ConvertTo-Json -Depth 12 -Compress)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($prevHash + $canonical))
        $recomputed = -join ($bytes | ForEach-Object { $_.ToString('x2') })
        if ($recomputed -ne $claimedCurrent) {
            return [PSCustomObject]@{ Valid = $false; Checked = $seq; FirstBreakSequence = $seq; Reason = 'current_hash_mismatch' }
        }
        $prevHash = $claimedCurrent
    }

    return [PSCustomObject]@{ Valid = $true; Checked = $seq; FirstBreakSequence = $null }
}

Export-ModuleMember -Function New-AresCaseId, Initialize-AresCase, Write-AresEvent, `
    Write-AresTransaction, Get-AresTransactions, Test-AresLogChainIntegrity, Get-AresCanonicalJson
