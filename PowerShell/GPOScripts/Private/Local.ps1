function Get-GpoRegistryState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if ($Path -notmatch '^HKLM:\\(.+)$') { throw 'Only the local machine registry is supported.' }
    $subPath = $Matches[1]
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $base.OpenSubKey($subPath, $false)
        $exists = $null -ne $key
        $hasValue = $exists -and ($Name -in $key.GetValueNames())
        $value = $null
        $kind = $null
        if ($hasValue) {
            $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = $key.GetValueKind($Name).ToString()
        }
        [pscustomobject]@{KeyExists=$exists; ValueExists=$hasValue; Type=$kind; Value=$value}
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function Set-GpoRegistryState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$State)
    if ($Path -notmatch '^HKLM:\\(.+)$') { throw 'Only the local machine registry is supported.' }
    $subPath = $Matches[1]
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        if ($State.ValueExists) {
            # CreateSubKey opens an existing key without replacing its other values or subkeys.
            $key = $base.CreateSubKey($subPath)
            $value = switch ([string]$State.Type) {
                'DWord' { [int]$State.Value }
                'QWord' { [long]$State.Value }
                'Binary' { ,([byte[]]$State.Value) }
                'None' { ,([byte[]]$State.Value) }
                'MultiString' { ,([string[]]$State.Value) }
                'String' { [string]$State.Value }
                'ExpandString' { [string]$State.Value }
                default { throw 'The recovery record contains an unsupported registry type.' }
            }
            $kind = [System.Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$State.Type, $true)
            $key.SetValue($Name, $value, $kind)
        } else {
            $key = $base.OpenSubKey($subPath, $true)
            if ($null -ne $key) { $key.DeleteValue($Name, $false) }
            # Empty keys remain. Removing a parent could remove unrelated concurrent settings.
        }
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function Get-GpoFeatureState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $features = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)
    $feature = @($features | Where-Object FeatureName -eq $Name)
    if ($feature.Count -gt 1) { throw "The feature query returned duplicate results for $Name." }
    if (-not $feature.Count) { return 'NotPresent' }
    [string]$feature[0].State
}

function Set-GpoFeatureState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][ValidateSet('Enabled', 'Disabled')][string]$State)
    if ($State -eq 'Disabled') {
        $null = Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop
    } else {
        $null = Enable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop
    }
}

function Test-GpoRegistryStateEqual {
    param([Parameter(Mandatory)]$Left, [Parameter(Mandatory)]$Right)
    if ([bool]$Left.ValueExists -ne [bool]$Right.ValueExists) { return $false }
    if (-not $Left.ValueExists) { return $true }
    return ($Left.Type -eq $Right.Type -and (Test-GpoValuesEqual $Left.Value $Right.Value))
}

function Assert-GpoRecoveryValue {
    param([Parameter(Mandatory)]$State)
    if ($State.ValueExists -isnot [bool] -or $State.KeyExists -isnot [bool]) { throw 'The recovery record has an invalid existence flag.' }
    if (-not $State.ValueExists) { return }
    $value = $State.Value
    switch ([string]$State.Type) {
        'DWord' {
            if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt [int]::MinValue -or $value -gt [int]::MaxValue) {
                throw 'The recovery record has an invalid DWORD value.'
            }
        }
        'QWord' { if ($value -isnot [int] -and $value -isnot [long]) { throw 'The recovery record has an invalid QWORD value.' } }
        { $_ -in @('String', 'ExpandString') } {
            if ($value -isnot [string] -or $value.Length -gt 1048576) { throw 'The recovery record has an invalid string value.' }
        }
        'MultiString' {
            if ($value -isnot [array] -or @($value | Where-Object { $_ -isnot [string] }).Count) { throw 'The recovery record has an invalid string array.' }
        }
        { $_ -in @('Binary', 'None') } {
            if ($value -isnot [array] -or @($value | Where-Object { ($_ -isnot [int] -and $_ -isnot [long] -and $_ -isnot [byte]) -or $_ -lt 0 -or $_ -gt 255 }).Count) {
                throw 'The recovery record has an invalid byte array.'
            }
        }
        default { throw 'The recovery record has an invalid registry type.' }
    }
}

function Get-GpoAssessment {
    [CmdletBinding()]
    param([string[]]$Id)
    $selection = @{}
    if ($PSBoundParameters.ContainsKey('Id')) { $selection.Id = $Id }
    $controls = @(Get-GpoControl @selection)
    $context = Get-GpoTargetContext
    foreach ($control in $controls) {
        try {
            $applicability = Test-GpoControlApplicability -Control $control -Context $context
            if (-not $applicability.Applicable) {
                New-GpoResult -Control $control -Status NotApplicable -Reason $applicability.Reason -Evidence $context
                continue
            }
            if ($control.Kind -eq 'Audit') {
                Invoke-GpoReadinessCheck -Control $control -Context $context
                continue
            }
            $matches = $true
            $evidence = @()
            if ($control.Kind -eq 'Registry') {
                foreach ($setting in $control.Registry) {
                    $actual = Get-GpoRegistryState -Path $setting.Path -Name $setting.Name
                    $expected = [pscustomobject]@{ValueExists=$true; Type=$setting.Type; Value=$setting.Value}
                    $match = Test-GpoRegistryStateEqual $actual $expected
                    if (-not $match) { $matches = $false }
                    $evidence += [pscustomobject]@{Path=$setting.Path; Name=$setting.Name; Actual=$actual; Expected=$expected; Matches=$match}
                }
            } else {
                foreach ($name in $control.Features) {
                    $state = Get-GpoFeatureState -Name $name
                    $match = $state -in @('Disabled', 'DisabledWithPayloadRemoved', 'NotPresent')
                    if (-not $match) { $matches = $false }
                    $evidence += [pscustomobject]@{Feature=$name; State=$state; Matches=$match}
                }
            }
            $status = if ($matches) { 'Compliant' } else { 'NonCompliant' }
            $reason = if ($matches) { 'The recorded configuration matches. Application behavior still requires validation.' } else { 'The recorded configuration differs. Defaults, policy ownership, and dependencies require review.' }
            New-GpoResult -Control $control -Status $status -Reason $reason -Evidence $evidence
        } catch {
            New-GpoResult -Control $control -Status Error -Reason $_.Exception.Message
        }
    }
}

function Invoke-GpoLocalApply {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Id,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BackupDirectory,
        [switch]$AcceptCompatibilityRisk
    )
    $controls = @(Get-GpoControl -Id $Id)
    $context = Get-GpoTargetContext
    if (-not $context.Supported) { throw $context.Reason }
    Assert-GpoAdministrator
    $changes = @()
    foreach ($control in $controls) {
        $applicability = Test-GpoControlApplicability -Control $control -Context $context
        if (-not $applicability.Applicable) { throw "$($control.Id): $($applicability.Reason)" }
        if ($control.Kind -eq 'Audit') { throw "$($control.Id) is an assessment control. It cannot apply settings." }
        if ($control.CompatibilityRisk -and -not $AcceptCompatibilityRisk) {
            throw "$($control.Id) can interrupt dependent applications. Assess dependencies and specify -AcceptCompatibilityRisk after validation."
        }
        if ($control.Kind -eq 'Registry') {
            foreach ($setting in $control.Registry) {
                $before = Get-GpoRegistryState -Path $setting.Path -Name $setting.Name
                $after = [pscustomobject]@{KeyExists=$true; ValueExists=$true; Type=$setting.Type; Value=$setting.Value}
                if (-not (Test-GpoRegistryStateEqual $before $after)) {
                    $changes += [pscustomobject]@{ControlId=$control.Id; Kind='Registry'; Path=$setting.Path; Name=$setting.Name; Before=$before; After=$after}
                }
            }
        } else {
            foreach ($name in $control.Features) {
                $before = Get-GpoFeatureState -Name $name
                if ($before -notin @('Enabled', 'Disabled', 'DisabledWithPayloadRemoved', 'NotPresent')) {
                    throw "$name has state $before. Complete servicing and restart before applying settings."
                }
                if ($before -eq 'Enabled') {
                    $changes += [pscustomobject]@{ControlId=$control.Id; Kind='Feature'; Name=$name; Before=$before; After='Disabled'}
                }
            }
        }
    }
    $operation = [guid]::NewGuid().ToString()
    $snapshotPath = Join-Path $BackupDirectory ("local-{0}.json" -f $operation)
    if (-not $changes.Count) { return [pscustomobject]@{Status='Unchanged'; ChangeCount=0; SnapshotPath=$null; RestartRequired=$false} }
    if (-not $PSCmdlet.ShouldProcess($context.ComputerName, "Apply $($changes.Count) changes and save recovery state")) {
        return [pscustomobject]@{Status='Planned'; ChangeCount=$changes.Count; SnapshotPath=$null; RestartRequired=[bool](@($controls | Where-Object RestartRequired).Count)}
    }
    $snapshot = [pscustomobject]@{
        SchemaVersion=1; Artifact='GPOScripts.LocalState'; OperationId=$operation
        CreatedUtc=[datetime]::UtcNow.ToString('o'); Context=$context; Changes=$changes
    }
    Write-GpoJson -InputObject $snapshot -Path $snapshotPath
    $restart = [bool](@($controls | Where-Object RestartRequired).Count)
    try {
        foreach ($change in $changes) {
            if ($change.Kind -eq 'Registry') {
                $current = Get-GpoRegistryState -Path $change.Path -Name $change.Name
                if (-not (Test-GpoRegistryStateEqual $current $change.Before)) { throw "A setting changed after assessment: $($change.Name)." }
                Set-GpoRegistryState -Path $change.Path -Name $change.Name -State $change.After
                $actual = Get-GpoRegistryState -Path $change.Path -Name $change.Name
                if (-not (Test-GpoRegistryStateEqual $actual $change.After)) { throw "Verification failed for $($change.Name)." }
            } else {
                $current = Get-GpoFeatureState -Name $change.Name
                # Disabling a parent can already disable its child.
                if ($current -eq 'Enabled') { Set-GpoFeatureState -Name $change.Name -State Disabled }
                elseif ($current -notin @('Disabled', 'DisabledWithPayloadRemoved', 'DisablePending')) { throw "Unexpected feature state: $current." }
                $actual = Get-GpoFeatureState -Name $change.Name
                if ($actual -notin @('Disabled', 'DisabledWithPayloadRemoved', 'DisablePending')) { throw "Feature verification failed for $($change.Name)." }
                if ($actual -eq 'DisablePending') { $restart = $true }
            }
        }
        $result = [pscustomobject]@{Status='Configured'; ChangeCount=$changes.Count; SnapshotPath=$snapshotPath; RestartRequired=$restart; ApplicationValidation='Required'}
        Write-GpoJson -InputObject $result -Path ($snapshotPath + '.result.json')
        $result
    } catch {
        throw "Apply stopped. Some changes may remain. Recovery record: $snapshotPath. $($_.Exception.Message)"
    }
}

function Restore-GpoLocalState {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 4194304) { throw 'The recovery record is not a supported file.' }
    $snapshot = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($snapshot.SchemaVersion -ne 1 -or $snapshot.Artifact -ne 'GPOScripts.LocalState') { throw 'The recovery record has an unsupported format.' }
    $context = Get-GpoTargetContext
    if ($snapshot.Context.MachineId -ne $context.MachineId -or $snapshot.Context.ComputerName -ne $context.ComputerName) {
        throw 'The recovery record belongs to a different server.'
    }
    if ($snapshot.Context.Build -ne $context.Build -or $snapshot.Context.Role -ne $context.Role) { throw 'The server version or role changed. Review recovery manually.' }
    Assert-GpoAdministrator
    $changes = @($snapshot.Changes)
    if (-not $changes.Count -or $changes.Count -gt 256) { throw 'The recovery record has an invalid change count.' }
    $seen = @{}
    foreach ($change in $changes) {
        $control = Get-GpoControl -Id $change.ControlId
        if ($change.Kind -ne $control.Kind -or $control.Kind -eq 'Audit') { throw 'The recovery record has an invalid control kind.' }
        if ($change.Kind -eq 'Registry') {
            $allowed = @($control.Registry | Where-Object { $_.Path -eq $change.Path -and $_.Name -eq $change.Name })
            if ($allowed.Count -ne 1) { throw 'The recovery record contains a registry location outside its control.' }
            $identity = "$($change.Path)|$($change.Name)"
            $expected = [pscustomobject]@{ValueExists=$true; Type=$allowed[0].Type; Value=$allowed[0].Value}
            if (-not (Test-GpoRegistryStateEqual $change.After $expected)) { throw 'The control definition changed. Review recovery manually.' }
            Assert-GpoRecoveryValue -State $change.Before
            $current = Get-GpoRegistryState -Path $change.Path -Name $change.Name
            if (-not (Test-GpoRegistryStateEqual $current $change.Before) -and -not (Test-GpoRegistryStateEqual $current $change.After)) {
                throw "The current value changed after apply: $($change.Name). Review recovery manually."
            }
        } else {
            if ($change.Name -notin $control.Features -or $change.Before -ne 'Enabled' -or $change.After -ne 'Disabled') {
                throw 'The recovery record has an invalid feature change.'
            }
            $identity = "Feature|$($change.Name)"
            $current = Get-GpoFeatureState -Name $change.Name
            if ($current -notin @('Enabled', 'Disabled')) { throw "Feature recovery requires completed servicing: $($change.Name), $current." }
        }
        if ($seen.ContainsKey($identity)) { throw 'The recovery record contains duplicate changes.' }
        $seen[$identity] = $true
    }
    if (-not $PSCmdlet.ShouldProcess($context.ComputerName, "Restore $($changes.Count) recorded settings")) {
        return [pscustomobject]@{Status='Planned'; ChangeCount=$changes.Count; SnapshotPath=$Path}
    }
    $recoveryPath = Join-Path $file.DirectoryName ('restore-' + [guid]::NewGuid().ToString('N') + '.json')
    Write-GpoJson -InputObject ([pscustomobject]@{Status='Started'; CreatedUtc=[datetime]::UtcNow.ToString('o'); Source=$Path; Context=$context}) -Path $recoveryPath
    try {
        # Restore parent features first. Feature servicing can also restore a child automatically.
        $restoreOrder = @($changes | Sort-Object @{Expression={if ($_.Kind -eq 'Feature' -and $_.Name -like '*Root') { 0 } else { 1 }}})
        foreach ($change in $restoreOrder) {
            if ($change.Kind -eq 'Registry') {
                $current = Get-GpoRegistryState -Path $change.Path -Name $change.Name
                if (Test-GpoRegistryStateEqual $current $change.Before) { continue }
                if (-not (Test-GpoRegistryStateEqual $current $change.After)) { throw 'A registry value changed during recovery.' }
                Set-GpoRegistryState -Path $change.Path -Name $change.Name -State $change.Before
                if (-not (Test-GpoRegistryStateEqual (Get-GpoRegistryState -Path $change.Path -Name $change.Name) $change.Before)) {
                    throw "Recovery verification failed for $($change.Name)."
                }
            } else {
                $state = Get-GpoFeatureState -Name $change.Name
                if ($state -in @('Enabled', 'EnablePending')) { continue }
                if ($state -ne 'Disabled') { throw 'Feature state changed during recovery.' }
                Set-GpoFeatureState -Name $change.Name -State Enabled
                if ((Get-GpoFeatureState -Name $change.Name) -notin @('Enabled', 'EnablePending')) { throw 'Feature recovery verification failed.' }
            }
        }
        $result = [pscustomobject]@{Status='Restored'; ChangeCount=$changes.Count; SnapshotPath=$Path; RestartRequired=$true; EmptyKeys='Retained'; ApplicationValidation='Required'}
        Write-GpoJson -InputObject $result -Path ($recoveryPath + '.result.json')
        $result
    } catch {
        throw "Recovery stopped. Some settings may remain changed. Record: $Path. $($_.Exception.Message)"
    }
}
