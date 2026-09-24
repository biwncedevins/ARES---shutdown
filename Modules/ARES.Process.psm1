#Requires -Version 5.1
<#
    ARES.Process.psm1
    ------------------
    Process enumeration, ancestry-tree construction, and leaf-to-root
    containment/termination.
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'ARES.Logging.psm1') -Force

# Processes ARES will never terminate outright, regardless of score,
# absent an explicit high-confidence LOCKDOWN override. This is a floor,
# not the whole trust model - scoring still runs against these.
$Script:AresCriticalProcessNames = @(
    'system','smss.exe','csrss.exe','wininit.exe','services.exe','lsass.exe',
    'winlogon.exe','svchost.exe','explorer.exe','dwm.exe','fontdrvhost.exe',
    'sihost.exe','registry','memory compression','ares-shutdown.exe','ares.service.exe'
)

function Get-AresProcessInventory {
    <#
        Enumerates all processes with the metadata fields required by the
        spec, and returns a flat list plus a reconstructed tree.
    #>
    param([Parameter(Mandatory)]$Case)

    $inventory = @()
    try {
        $cimProcs = Get-CimInstance Win32_Process -ErrorAction Stop
    } catch {
        Write-AresEvent -Case $Case -EventType 'PROCESS_ENUM' -Severity CRITICAL -Result FAILED -Message $_.Exception.Message
        return @()
    }

    # Pre-fetch connection -> PID map once (cheap relative to per-process calls)
    $connByPid = @{}
    try {
        Get-NetTCPConnection -ErrorAction Stop | Group-Object OwningProcess | ForEach-Object {
            $connByPid[[int]$_.Name] = $_.Group | ForEach-Object {
                [ordered]@{
                    local  = "$($_.LocalAddress):$($_.LocalPort)"
                    remote = "$($_.RemoteAddress):$($_.RemotePort)"
                    state  = "$($_.State)"
                }
            }
        }
    } catch { }

    foreach ($p in $cimProcs) {
        $exePath = $p.ExecutablePath
        $sha256 = $null
        $sigStatus = 'NOT_AVAILABLE'
        $signer = $null

        if ($exePath -and (Test-Path -LiteralPath $exePath -ErrorAction SilentlyContinue)) {
            try {
                $sha256 = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256 -ErrorAction Stop).Hash
            } catch { $sha256 = $null }
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $exePath -ErrorAction Stop
                $sigStatus = "$($sig.Status)"
                if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            } catch { $sigStatus = 'NOT_AVAILABLE' }
        }

        $integrity = 'UNKNOWN'
        try {
            $procHandle = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
        } catch { }

        $entry = [ordered]@{
            pid_             = $p.ProcessId
            ppid             = $p.ParentProcessId
            name             = $p.Name
            path             = $exePath
            command_line     = $p.CommandLine
            user             = $(try { (Invoke-CimMethod -InputObject $p -MethodName GetOwner).User } catch { $null })
            creation_time    = $(try { $p.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ') } catch { $null })
            sha256           = $sha256
            signature_status = $sigStatus
            signer           = $signer
            connections      = $connByPid[[int]$p.ProcessId]
            children         = @()
        }
        $inventory += [PSCustomObject]$entry
    }

    # Build tree: map pid -> node, attach children to parents where parent exists.
    $byPid = @{}
    foreach ($e in $inventory) { $byPid[[int]$e.pid_] = $e }
    $roots = @()
    foreach ($e in $inventory) {
        $parent = $byPid[[int]$e.ppid]
        if ($parent -and $parent.pid_ -ne $e.pid_) {
            $parent.children += $e.pid_
        } else {
            $roots += $e.pid_
        }
    }

    $treeOut = [ordered]@{
        captured_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        roots        = $roots
        processes    = $inventory
    }

    $treePath = Join-Path $Case.EvidenceDir 'process_tree.json'
    try {
        ($treeOut | ConvertTo-Json -Depth 10) | Set-Content -Path $treePath -Encoding UTF8
        Write-AresEvent -Case $Case -EventType 'PROCESS_ENUM_COMPLETE' -Severity INFO -Result SUCCESS `
            -Message "Enumerated $($inventory.Count) processes" -Data @{ count = $inventory.Count }
    } catch {
        Write-AresEvent -Case $Case -EventType 'PROCESS_TREE_SAVE' -Severity MEDIUM -Result FAILED -Message $_.Exception.Message
    }

    return $inventory
}

function Get-AresProcessAncestry {
    <#
        Returns the full ancestor chain (root..process) for a given PID from
        an already-collected inventory list.
    #>
    param(
        [Parameter(Mandatory)][array]$Inventory,
        [Parameter(Mandatory)][int]$ProcessId
    )
    $byPid = @{}
    foreach ($e in $Inventory) { $byPid[[int]$e.pid_] = $e }

    $chain = @()
    $cur = $byPid[$ProcessId]
    $seen = @{}
    while ($cur -and -not $seen.ContainsKey([int]$cur.pid_)) {
        $chain = @($cur) + $chain
        $seen[[int]$cur.pid_] = $true
        $cur = $byPid[[int]$cur.ppid]
    }
    return $chain
}

function Test-AresProcessIsCritical {
    param([Parameter(Mandatory)][string]$Name)
    return $Script:AresCriticalProcessNames -contains $Name.ToLowerInvariant()
}

function Stop-AresProcessTree {
    <#
        Terminates a process and its descendants, leaves-first. Captures
        pre-termination evidence for each node. Never touches a node on the
        critical list unless -AllowCriticalOverride is explicitly set
        (LOCKDOWN profile only), and even then logs a CRITICAL-severity
        warning event before acting.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][array]$Inventory,
        [Parameter(Mandatory)][int]$RootProcessId,
        [string]$Reason = 'behavioral score threshold exceeded',
        [switch]$AllowCriticalOverride
    )

    $byPid = @{}
    foreach ($e in $Inventory) { $byPid[[int]$e.pid_] = $e }

    function Get-Descendants([int]$rootPid) {
        $result = @()
        $queue = New-Object System.Collections.Generic.Queue[int]
        $queue.Enqueue($rootPid)
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            $node = $byPid[$cur]
            if (-not $node) { continue }
            $result += $node
            foreach ($childPid in $node.children) { $queue.Enqueue([int]$childPid) }
        }
        return $result
    }

    $subtree = Get-Descendants -rootPid $RootProcessId
    # Order leaves-first: process with no children in the subtree first.
    $childCount = @{}
    foreach ($n in $subtree) { $childCount[[int]$n.pid_] = ($n.children | Where-Object { $byPid.ContainsKey([int]$_) }).Count }
    $ordered = $subtree | Sort-Object { $childCount[[int]$_.pid_] }

    $results = @()
    foreach ($node in $ordered) {
        $isCritical = Test-AresProcessIsCritical -Name $node.name
        if ($isCritical -and -not $AllowCriticalOverride) {
            Write-AresEvent -Case $Case -EventType 'PROCESS_TERMINATION_SKIPPED_CRITICAL' -Severity CRITICAL -Result 'NOT_AVAILABLE' `
                -Message "Refused to terminate protected process $($node.name) (PID $($node.pid_))" -Data @{ pid = $node.pid_; name = $node.name }
            $results += [PSCustomObject]@{ pid = $node.pid_; name = $node.name; status = 'SKIPPED_CRITICAL' }
            continue
        }

        # Evidence capture before action.
        $ancestry = Get-AresProcessAncestry -Inventory $Inventory -ProcessId $node.pid_
        $evidence = [ordered]@{
            pid_              = $node.pid_
            name              = $node.name
            path              = $node.path
            command_line      = $node.command_line
            sha256            = $node.sha256
            signature_status  = $node.signature_status
            signer            = $node.signer
            connections       = $node.connections
            ancestry          = $ancestry | ForEach-Object { @{ pid = $_.pid_; name = $_.name; path = $_.path } }
            reason            = $Reason
            captured_utc      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        }
        $evPath = Join-Path $Case.EvidenceDir "process_evidence_$($node.pid_).json"
        try { ($evidence | ConvertTo-Json -Depth 10) | Set-Content -Path $evPath -Encoding UTF8 } catch { }

        try {
            $proc = Get-Process -Id $node.pid_ -ErrorAction Stop
            Stop-Process -Id $node.pid_ -Force -ErrorAction Stop
            Write-AresTransaction -Case $Case -Action 'terminate_process' -Target "$($node.name) (PID $($node.pid_))" `
                -OriginalState 'running' -NewState 'terminated' -Reversible $false -Result SUCCESS
            Write-AresEvent -Case $Case -EventType 'PROCESS_TERMINATED' -Severity HIGH -Result SUCCESS `
                -Message $Reason -Data @{ pid = $node.pid_; name = $node.name; path = $node.path; sha256 = $node.sha256 }
            $results += [PSCustomObject]@{ pid = $node.pid_; name = $node.name; status = 'TERMINATED' }
        } catch {
            $status = if ($_.Exception.Message -match 'Cannot find a process') { 'ALREADY_EXITED' } else { 'FAILED' }
            Write-AresEvent -Case $Case -EventType 'PROCESS_TERMINATION_FAILED' -Severity HIGH -Result $(if ($status -eq 'ALREADY_EXITED') { 'NOT_AVAILABLE' } else { 'FAILED' }) `
                -Message $_.Exception.Message -Data @{ pid = $node.pid_; name = $node.name }
            $results += [PSCustomObject]@{ pid = $node.pid_; name = $node.name; status = $status }
        }
    }

    return $results
}

Export-ModuleMember -Function Get-AresProcessInventory, Get-AresProcessAncestry, `
    Test-AresProcessIsCritical, Stop-AresProcessTree
