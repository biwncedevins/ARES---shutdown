#Requires -Version 5.1
<#
    ARES.Network.psm1
    ------------------
    Phase 1: Immediate network containment.

    Policies:
      suspicious-only  - block only flagged processes/remote endpoints
      isolate-all       - block all outbound/inbound except policy-defined
                           exceptions (DEFAULT)
      hard-disconnect   - disable network adapters outright, record state
                           for restoration

    All rules created here are tagged with a case-specific group name so
    they can be enumerated and removed by the recovery engine, and system
    firewall policy/profile settings are never permanently altered.
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'ARES.Logging.psm1') -Force

function Get-AresFirewallRuleGroup {
    param([Parameter(Mandatory)]$Case)
    return "ARES-$($Case.CaseId)"
}

function Get-AresNetworkSnapshot {
    <#
        Captures current interface state, IP config, DNS config, and active
        TCP/UDP endpoints with owning PID where available. Never blocks on
        this - best-effort, each sub-collection independently fault-tolerant.
    #>
    param([Parameter(Mandatory)]$Case)

    $snapshot = [ordered]@{
        captured_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        interfaces   = @()
        ip_config    = @()
        dns_config   = @()
        tcp          = @()
        udp          = @()
    }

    try {
        $snapshot.interfaces = Get-NetAdapter | ForEach-Object {
            [ordered]@{
                Name = $_.Name; InterfaceDescription = $_.InterfaceDescription
                Status = $_.Status; MacAddress = $_.MacAddress
                ifIndex = $_.ifIndex; LinkSpeed = "$($_.LinkSpeed)"
            }
        }
    } catch {
        Write-AresEvent -Case $Case -EventType 'NET_SNAPSHOT_INTERFACES' -Severity MEDIUM -Result FAILED -Message $_.Exception.Message
    }

    try {
        $snapshot.ip_config = Get-NetIPAddress | ForEach-Object {
            [ordered]@{ ifIndex = $_.ifIndex; IPAddress = $_.IPAddress; PrefixLength = $_.PrefixLength; AddressFamily = "$($_.AddressFamily)" }
        }
    } catch {
        Write-AresEvent -Case $Case -EventType 'NET_SNAPSHOT_IPCONFIG' -Severity MEDIUM -Result FAILED -Message $_.Exception.Message
    }

    try {
        $snapshot.dns_config = Get-DnsClientServerAddress | ForEach-Object {
            [ordered]@{ InterfaceAlias = $_.InterfaceAlias; ServerAddresses = @($_.ServerAddresses) }
        }
    } catch {
        Write-AresEvent -Case $Case -EventType 'NET_SNAPSHOT_DNS' -Severity MEDIUM -Result FAILED -Message $_.Exception.Message
    }

    try {
        $snapshot.tcp = Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort
                State = "$($_.State)"; OwningProcess = $_.OwningProcess
                timestamp_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
            }
        }
    } catch {
        Write-AresEvent -Case $Case -EventType 'NET_SNAPSHOT_TCP' -Severity MEDIUM -Result FAILED -Message $_.Exception.Message
    }

    try {
        $snapshot.udp = Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; OwningProcess = $_.OwningProcess
            }
        }
    } catch {
        Write-AresEvent -Case $Case -EventType 'NET_SNAPSHOT_UDP' -Severity MEDIUM -Result FAILED -Message $_.Exception.Message
    }

    $snapshotPath = Join-Path $Case.EvidenceDir 'network.json'
    try {
        ($snapshot | ConvertTo-Json -Depth 10) | Set-Content -Path $snapshotPath -Encoding UTF8
        Write-AresEvent -Case $Case -EventType 'NET_SNAPSHOT_SAVED' -Severity INFO -Result SUCCESS -Message $snapshotPath
    } catch {
        Write-AresEvent -Case $Case -EventType 'NET_SNAPSHOT_SAVE' -Severity HIGH -Result FAILED -Message $_.Exception.Message
    }

    return $snapshot
}

function Invoke-AresNetworkContainment {
    <#
        Applies the configured containment policy. Returns a result object
        with an explicit Status - never silently claims success.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][ValidateSet('suspicious-only','isolate-all','hard-disconnect')]
        [string]$Policy,
        [string[]]$AllowedExceptionPrograms = @(),   # policy-driven, not hard-coded
        [string[]]$AllowedExceptionRemoteIPs = @()
    )

    $group = Get-AresFirewallRuleGroup -Case $Case
    $result = [ordered]@{ policy = $Policy; status = 'FAILED'; rules_created = @(); errors = @() }

    switch ($Policy) {

        'hard-disconnect' {
            try {
                $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
                $originalState = $adapters | ForEach-Object { @{ Name = $_.Name; ifIndex = $_.ifIndex; Status = $_.Status } }
                $stateFile = Join-Path $Case.EvidenceDir 'interface_state_before_disconnect.json'
                ($originalState | ConvertTo-Json -Depth 6) | Set-Content -Path $stateFile -Encoding UTF8

                foreach ($a in $adapters) {
                    try {
                        Disable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop
                        Write-AresTransaction -Case $Case -Action 'disable_network_adapter' -Target $a.Name `
                            -OriginalState 'Up' -NewState 'Disabled' -Reversible $true -Result SUCCESS
                    } catch {
                        $result.errors += "adapter $($a.Name): $($_.Exception.Message)"
                        Write-AresTransaction -Case $Case -Action 'disable_network_adapter' -Target $a.Name `
                            -OriginalState 'Up' -NewState $null -Reversible $true -Result FAILED
                    }
                }
                $result.status = if ($result.errors.Count -eq 0) { 'SUCCESS' } else { 'PARTIAL' }
            } catch {
                $result.errors += $_.Exception.Message
                $result.status = 'FAILED'
            }
        }

        'isolate-all' {
            # Block all outbound and inbound via a case-tagged, high-priority
            # firewall rule pair, then punch narrow, policy-driven holes.
            try {
                $ruleNameOut = "$group-block-outbound"
                $ruleNameIn  = "$group-block-inbound"

                New-NetFirewallRule -DisplayName $ruleNameOut -Group $group -Direction Outbound `
                    -Action Block -Enabled True -Profile Any -Priority 1 -ErrorAction Stop | Out-Null
                New-NetFirewallRule -DisplayName $ruleNameIn -Group $group -Direction Inbound `
                    -Action Block -Enabled True -Profile Any -ErrorAction Stop | Out-Null

                Write-AresTransaction -Case $Case -Action 'create_firewall_rule' -Target $ruleNameOut `
                    -OriginalState 'none' -NewState 'block-outbound-all' -Reversible $true -Result SUCCESS
                Write-AresTransaction -Case $Case -Action 'create_firewall_rule' -Target $ruleNameIn `
                    -OriginalState 'none' -NewState 'block-inbound-all' -Reversible $true -Result SUCCESS

                $result.rules_created += $ruleNameOut, $ruleNameIn

                foreach ($prog in $AllowedExceptionPrograms) {
                    $exName = "$group-allow-$([IO.Path]::GetFileNameWithoutExtension($prog))"
                    try {
                        New-NetFirewallRule -DisplayName $exName -Group $group -Direction Outbound `
                            -Action Allow -Program $prog -Enabled True -Profile Any -Priority 0 -ErrorAction Stop | Out-Null
                        Write-AresTransaction -Case $Case -Action 'create_firewall_exception' -Target $prog `
                            -OriginalState 'blocked' -NewState 'allowed' -Reversible $true -Result SUCCESS
                        $result.rules_created += $exName
                    } catch {
                        $result.errors += "exception $prog: $($_.Exception.Message)"
                    }
                }

                $result.status = if ($result.errors.Count -eq 0) { 'SUCCESS' } else { 'PARTIAL' }
            } catch {
                $result.errors += $_.Exception.Message
                $result.status = 'FAILED'
            }
        }

        'suspicious-only' {
            # Baseline pass creates no blanket rules; block rules are added
            # per-process/per-IP by Block-AresRemoteEndpoint /
            # Block-AresProcessNetwork as suspicious activity is scored.
            $result.status = 'SUCCESS'
            $result.rules_created += '(deferred - per-indicator blocking active)'
        }
    }

    Write-AresEvent -Case $Case -EventType 'NETWORK_CONTAINMENT_APPLIED' `
        -Severity $(if ($result.status -eq 'SUCCESS') { 'HIGH' } elseif ($result.status -eq 'PARTIAL') { 'HIGH' } else { 'CRITICAL' }) `
        -Result $result.status -Message "Policy=$Policy" -Data $result

    return [PSCustomObject]$result
}

function Block-AresRemoteEndpoint {
    <#
        Used under 'suspicious-only' policy (or as a supplemental measure
        under any policy) to block a specific remote IP tied to a
        high-confidence indicator.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$RemoteIp,
        [string]$Reason = 'suspicious remote endpoint'
    )
    $group = Get-AresFirewallRuleGroup -Case $Case
    $ruleName = "$group-block-ip-$RemoteIp"
    try {
        New-NetFirewallRule -DisplayName $ruleName -Group $group -Direction Outbound `
            -Action Block -RemoteAddress $RemoteIp -Enabled True -Profile Any -ErrorAction Stop | Out-Null
        Write-AresTransaction -Case $Case -Action 'block_remote_ip' -Target $RemoteIp `
            -OriginalState 'allowed' -NewState 'blocked' -Reversible $true -Result SUCCESS
        Write-AresEvent -Case $Case -EventType 'REMOTE_IP_BLOCKED' -Severity HIGH -Result SUCCESS -Message $Reason -Data @{ ip = $RemoteIp }
        return 'SUCCESS'
    } catch {
        Write-AresEvent -Case $Case -EventType 'REMOTE_IP_BLOCKED' -Severity HIGH -Result FAILED -Message $_.Exception.Message -Data @{ ip = $RemoteIp }
        return 'FAILED'
    }
}

function Remove-AresNetworkContainment {
    <#
        Recovery: removes every firewall rule tagged with this case's group
        and, if a hard-disconnect was performed, re-enables the recorded
        adapters. Explicit, operator-invoked only - never automatic on exit.
    #>
    param([Parameter(Mandatory)]$Case)

    $group = Get-AresFirewallRuleGroup -Case $Case
    $summary = [ordered]@{ rules_removed = 0; adapters_restored = 0; errors = @() }

    try {
        $rules = Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
        foreach ($r in $rules) {
            try {
                Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop
                $summary.rules_removed++
                Write-AresTransaction -Case $Case -Action 'remove_firewall_rule' -Target $r.DisplayName `
                    -OriginalState 'active' -NewState 'removed' -Reversible $false -Result SUCCESS
            } catch {
                $summary.errors += "$($r.DisplayName): $($_.Exception.Message)"
            }
        }
    } catch {
        $summary.errors += $_.Exception.Message
    }

    $stateFile = Join-Path $Case.EvidenceDir 'interface_state_before_disconnect.json'
    if (Test-Path $stateFile) {
        try {
            $originalState = Get-Content $stateFile -Raw | ConvertFrom-Json
            foreach ($a in $originalState) {
                try {
                    Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop
                    $summary.adapters_restored++
                    Write-AresTransaction -Case $Case -Action 'enable_network_adapter' -Target $a.Name `
                        -OriginalState 'Disabled' -NewState 'Up' -Reversible $false -Result SUCCESS
                } catch {
                    $summary.errors += "$($a.Name): $($_.Exception.Message)"
                }
            }
        } catch {
            $summary.errors += $_.Exception.Message
        }
    }

    Write-AresEvent -Case $Case -EventType 'NETWORK_CONTAINMENT_REMOVED' -Severity MEDIUM `
        -Result $(if ($summary.errors.Count -eq 0) { 'SUCCESS' } else { 'PARTIAL' }) -Data $summary

    return [PSCustomObject]$summary
}

Export-ModuleMember -Function Get-AresNetworkSnapshot, Invoke-AresNetworkContainment, `
    Block-AresRemoteEndpoint, Remove-AresNetworkContainment, Get-AresFirewallRuleGroup
