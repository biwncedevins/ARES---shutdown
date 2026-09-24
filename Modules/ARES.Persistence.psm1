#Requires -Version 5.1
<#
    ARES.Persistence.psm1
    -----------------------
    Enumerates common Windows persistence mechanisms and, on request,
    disables (never blind-deletes) suspicious entries following:

        capture -> disable/isolate -> record -> preserve -> reversible recovery
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'ARES.Logging.psm1') -Force

$Script:AresRunKeyPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)

$Script:AresStartupFolders = @(
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'),
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
)

function Get-AresPersistenceFindings {
    param([Parameter(Mandatory)]$Case)

    $findings = @()

    # --- Run / RunOnce keys ---
    foreach ($keyPath in $Script:AresRunKeyPaths) {
        try {
            if (Test-Path $keyPath) {
                $item = Get-Item -Path $keyPath -ErrorAction Stop
                foreach ($valueName in $item.Property) {
                    $findings += [PSCustomObject]@{
                        type       = 'RunKey'
                        location   = $keyPath
                        name       = $valueName
                        value      = (Get-ItemProperty -Path $keyPath -Name $valueName).$valueName
                        risk_hint  = 'review'
                    }
                }
            }
        } catch {
            Write-AresEvent -Case $Case -EventType 'PERSISTENCE_SCAN_RUNKEY' -Severity LOW -Result FAILED -Message "$keyPath : $($_.Exception.Message)"
        }
    }

    # --- Startup folders ---
    foreach ($folder in $Script:AresStartupFolders) {
        try {
            if (Test-Path $folder) {
                Get-ChildItem -Path $folder -File -ErrorAction Stop | ForEach-Object {
                    $findings += [PSCustomObject]@{
                        type      = 'StartupFolder'
                        location  = $folder
                        name      = $_.Name
                        value     = $_.FullName
                        risk_hint = 'review'
                    }
                }
            }
        } catch {
            Write-AresEvent -Case $Case -EventType 'PERSISTENCE_SCAN_STARTUP' -Severity LOW -Result FAILED -Message "$folder : $($_.Exception.Message)"
        }
    }

    # --- Scheduled Tasks ---
    try {
        Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
            $findings += [PSCustomObject]@{
                type      = 'ScheduledTask'
                location  = $_.TaskPath
                name      = $_.TaskName
                value     = $actions
                risk_hint = 'review'
            }
        }
    } catch {
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_SCAN_TASKS' -Severity LOW -Result FAILED -Message $_.Exception.Message
    }

    # --- Services (non-Microsoft, auto-start) ---
    try {
        Get-CimInstance Win32_Service -Filter "StartMode='Auto'" -ErrorAction Stop | ForEach-Object {
            $findings += [PSCustomObject]@{
                type      = 'Service'
                location  = 'Services'
                name      = $_.Name
                value     = $_.PathName
                risk_hint = 'review'
            }
        }
    } catch {
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_SCAN_SERVICES' -Severity LOW -Result FAILED -Message $_.Exception.Message
    }

    # --- WMI Event Subscriptions (classic fileless persistence vector) ---
    try {
        $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop
        foreach ($c in $consumers) {
            $findings += [PSCustomObject]@{
                type      = 'WmiEventConsumer'
                location  = 'root\subscription'
                name      = $c.Name
                value     = ($c | ConvertTo-Json -Compress -Depth 3)
                risk_hint = 'high-review'
            }
        }
    } catch {
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_SCAN_WMI' -Severity LOW -Result FAILED -Message $_.Exception.Message
    }

    $outPath = Join-Path $Case.EvidenceDir 'persistence.json'
    try {
        ($findings | ConvertTo-Json -Depth 8) | Set-Content -Path $outPath -Encoding UTF8
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_SCAN_COMPLETE' -Severity INFO -Result SUCCESS -Message "$($findings.Count) entries found"
    } catch {
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_SCAN_SAVE' -Severity MEDIUM -Result FAILED -Message $_.Exception.Message
    }

    return $findings
}

function Disable-AresRunKeyEntry {
    <#
        "Disables" a Run/RunOnce value by renaming it (prefixing with
        ARES_DISABLED_) rather than deleting it, and records the original
        state as a reversible transaction.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$ValueName,
        [string]$Reason = 'suspicious persistence entry'
    )
    try {
        $originalValue = (Get-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction Stop).$ValueName
        $newName = "ARES_DISABLED_$ValueName"
        New-ItemProperty -Path $KeyPath -Name $newName -Value $originalValue -PropertyType String -Force -ErrorAction Stop | Out-Null
        Remove-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction Stop

        Write-AresTransaction -Case $Case -Action 'disable_registry_value' -Target "$KeyPath\$ValueName" `
            -OriginalState $originalValue -NewState "renamed_to_$newName" -Reversible $true -Result SUCCESS
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_DISABLED' -Severity HIGH -Result SUCCESS `
            -Message $Reason -Data @{ key = $KeyPath; value_name = $ValueName }
        return 'SUCCESS'
    } catch {
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_DISABLE_FAILED' -Severity HIGH -Result FAILED `
            -Message $_.Exception.Message -Data @{ key = $KeyPath; value_name = $ValueName }
        return 'FAILED'
    }
}

function Disable-AresScheduledTask {
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$TaskPath,
        [Parameter(Mandatory)][string]$TaskName,
        [string]$Reason = 'suspicious scheduled task'
    )
    try {
        Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null
        Write-AresTransaction -Case $Case -Action 'disable_scheduled_task' -Target "$TaskPath$TaskName" `
            -OriginalState 'Enabled' -NewState 'Disabled' -Reversible $true -Result SUCCESS
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_DISABLED' -Severity HIGH -Result SUCCESS `
            -Message $Reason -Data @{ task = "$TaskPath$TaskName" }
        return 'SUCCESS'
    } catch {
        Write-AresEvent -Case $Case -EventType 'PERSISTENCE_DISABLE_FAILED' -Severity HIGH -Result FAILED `
            -Message $_.Exception.Message -Data @{ task = "$TaskPath$TaskName" }
        return 'FAILED'
    }
}

Export-ModuleMember -Function Get-AresPersistenceFindings, Disable-AresRunKeyEntry, Disable-AresScheduledTask
