#Requires -Version 5.1
<#
    ARES.Quarantine.psm1
    ----------------------
    Reversible file quarantine. Files are moved (never deleted) into the
    case quarantine directory, renamed to their SHA-256 to avoid
    double-execution risk, and stripped of executable ACL grants for
    ordinary users. A metadata sidecar records everything needed to restore.
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'ARES.Logging.psm1') -Force

function Move-AresFileToQuarantine {
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Reason = 'suspicious file'
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        Write-AresEvent -Case $Case -EventType 'QUARANTINE_SKIPPED_MISSING' -Severity LOW -Result 'NOT_AVAILABLE' `
            -Message "File no longer present: $FilePath"
        return [PSCustomObject]@{ status = 'NOT_AVAILABLE'; path = $FilePath }
    }

    $transactionId = [guid]::NewGuid().ToString()

    try {
        $fileInfo = Get-Item -LiteralPath $FilePath -ErrorAction Stop
        $hash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        $sig = $null
        try { $sig = (Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop).Status } catch { $sig = 'NOT_AVAILABLE' }

        $quarantineName = "$hash.quarantined"
        $quarantinePath = Join-Path $Case.QuarantineDir $quarantineName

        Move-Item -LiteralPath $FilePath -Destination $quarantinePath -Force -ErrorAction Stop

        # Strip execute/write for ordinary users on the quarantined copy.
        try {
            $acl = Get-Acl -Path $quarantinePath
            $acl.SetAccessRuleProtection($true, $false)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','Allow')
            $acl.AddAccessRule($rule)
            $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','Allow')
            $acl.AddAccessRule($sysRule)
            Set-Acl -Path $quarantinePath -AclObject $acl
        } catch { }

        $metadata = [ordered]@{
            transaction_id     = $transactionId
            case_id            = $Case.CaseId
            original_path      = $FilePath
            original_filename  = $fileInfo.Name
            quarantine_path    = $quarantinePath
            sha256             = $hash
            file_size          = $fileInfo.Length
            created_utc        = $fileInfo.CreationTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
            modified_utc       = $fileInfo.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
            signature_status   = $sig
            reason             = $Reason
            quarantined_utc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        }

        $metaPath = "$quarantinePath.meta.json"
        ($metadata | ConvertTo-Json -Depth 6) | Set-Content -Path $metaPath -Encoding UTF8

        Write-AresTransaction -Case $Case -Action 'quarantine_file' -Target $FilePath `
            -OriginalState $FilePath -NewState $quarantinePath -Reversible $true -Result SUCCESS
        Write-AresEvent -Case $Case -EventType 'FILE_QUARANTINED' -Severity HIGH -Result SUCCESS `
            -Message $Reason -Data @{ original_path = $FilePath; sha256 = $hash; quarantine_path = $quarantinePath }

        return [PSCustomObject]@{ status = 'SUCCESS'; metadata = $metadata }

    } catch {
        Write-AresEvent -Case $Case -EventType 'FILE_QUARANTINE_FAILED' -Severity HIGH -Result FAILED `
            -Message $_.Exception.Message -Data @{ path = $FilePath }
        return [PSCustomObject]@{ status = 'FAILED'; path = $FilePath; error = $_.Exception.Message }
    }
}

function Restore-AresQuarantinedFile {
    <#
        Explicit, operator-invoked recovery of a single quarantined file.
        Refuses to overwrite an existing file at the original path unless
        -Force is supplied.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$QuarantinePath,
        [switch]$Force
    )

    $metaPath = "$QuarantinePath.meta.json"
    if (-not (Test-Path $metaPath)) {
        Write-AresEvent -Case $Case -EventType 'QUARANTINE_RESTORE_FAILED' -Severity MEDIUM -Result FAILED -Message "Missing metadata sidecar for $QuarantinePath"
        return [PSCustomObject]@{ status = 'FAILED'; reason = 'missing_metadata' }
    }
    try {
        $meta = Get-Content -Path $metaPath -Raw | ConvertFrom-Json
        if ((Test-Path $meta.original_path) -and -not $Force) {
            Write-AresEvent -Case $Case -EventType 'QUARANTINE_RESTORE_BLOCKED' -Severity MEDIUM -Result FAILED `
                -Message "Original path already occupied: $($meta.original_path)"
            return [PSCustomObject]@{ status = 'FAILED'; reason = 'destination_exists' }
        }
        Move-Item -LiteralPath $QuarantinePath -Destination $meta.original_path -Force:$Force -ErrorAction Stop
        Write-AresTransaction -Case $Case -Action 'restore_quarantined_file' -Target $meta.original_path `
            -OriginalState $QuarantinePath -NewState $meta.original_path -Reversible $false -Result SUCCESS
        Write-AresEvent -Case $Case -EventType 'FILE_RESTORED' -Severity MEDIUM -Result SUCCESS -Message $meta.original_path
        return [PSCustomObject]@{ status = 'SUCCESS'; path = $meta.original_path }
    } catch {
        Write-AresEvent -Case $Case -EventType 'QUARANTINE_RESTORE_FAILED' -Severity MEDIUM -Result FAILED -Message $_.Exception.Message
        return [PSCustomObject]@{ status = 'FAILED'; reason = $_.Exception.Message }
    }
}

function Get-AresQuarantineManifest {
    param([Parameter(Mandatory)]$Case)
    $items = Get-ChildItem -Path $Case.QuarantineDir -Filter '*.meta.json' -ErrorAction SilentlyContinue |
        ForEach-Object { Get-Content -Path $_.FullName -Raw | ConvertFrom-Json }
    return $items
}

Export-ModuleMember -Function Move-AresFileToQuarantine, Restore-AresQuarantinedFile, Get-AresQuarantineManifest
