BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../PowerShell/GPOScripts/GPOScripts.psd1') -Force
}

Describe 'Local changes and recorded recovery' {
    InModuleScope GPOScripts {
        BeforeEach {
            $script:memoryRegistry = @{}
            $script:testControl = Get-GpoControl -Id LlmnrDisabled
            $script:testSetting = $script:testControl.Registry[0]
            $script:testKey = "$($script:testSetting.Path)|$($script:testSetting.Name)"
            Mock Get-GpoTargetContext {
                [pscustomobject]@{ComputerName='LAB-SERVER'; MachineId='test-machine'; Version='2022'; Build=20348; Role='MemberServer'; Supported=$true; Reason='Supported'; PowerShellVersion='5.1'}
            }
            Mock Assert-GpoAdministrator {}
            Mock Get-GpoRegistryState {
                param($Path, $Name)
                $key = "$Path|$Name"
                if ($script:memoryRegistry.ContainsKey($key)) { return $script:memoryRegistry[$key] }
                [pscustomobject]@{KeyExists=$false; ValueExists=$false; Type=$null; Value=$null}
            }
            Mock Set-GpoRegistryState {
                param($Path, $Name, $State)
                $script:memoryRegistry["$Path|$Name"] = [pscustomobject]@{KeyExists=$true; ValueExists=$State.ValueExists; Type=$State.Type; Value=$State.Value}
            }
            Mock Get-GpoFeatureState { throw 'An unexpected feature read reached the test boundary.' }
            Mock Set-GpoFeatureState { throw 'An unexpected feature change reached the test boundary.' }
            $script:backupDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        }

        It 'assesses missing values without creating files or settings' {
            $result = Get-GpoAssessment -Id LlmnrDisabled
            $result.Status | Should -Be 'NonCompliant'
            Should -Invoke Set-GpoRegistryState -Times 0 -Exactly
            Test-Path -LiteralPath $script:backupDirectory | Should -BeFalse
        }

        It 'reports inaccessible registry evidence as an error' {
            Mock Get-GpoRegistryState { throw 'Access denied.' }
            (Get-GpoAssessment -Id LlmnrDisabled).Status | Should -Be 'Error'
        }

        It 'does not apply an audit control' {
            { Invoke-GpoLocalApply -Id KerberosReadiness -BackupDirectory $script:backupDirectory -Confirm:$false } | Should -Throw '*assessment control*'
            Should -Invoke Set-GpoRegistryState -Times 0 -Exactly
        }

        It 'requires acceptance of compatibility risk before mutation' {
            { Invoke-GpoLocalApply -Id Tls10Disabled -BackupDirectory $script:backupDirectory -Confirm:$false } | Should -Throw '*AcceptCompatibilityRisk*'
            Should -Invoke Set-GpoRegistryState -Times 0 -Exactly
        }

        It 'rejects controls for a different server role before changes' {
            { Invoke-GpoLocalApply -Id LdapServerSigningRequired -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false } | Should -Throw '*server role*'
            Should -Invoke Set-GpoRegistryState -Times 0 -Exactly
        }

        It 'rejects unsupported targets' {
            Mock Get-GpoTargetContext { [pscustomobject]@{Supported=$false; Reason='Unsupported server.'} }
            { Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false } | Should -Throw '*Unsupported server*'
        }

        It 'creates no recovery file or registry value during WhatIf' {
            $result = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -WhatIf
            $result.Status | Should -Be 'Planned'
            Should -Invoke Set-GpoRegistryState -Times 0 -Exactly
            Test-Path -LiteralPath $script:backupDirectory | Should -BeFalse
        }

        It 'saves recovery state before applying any value' {
            Mock Set-GpoRegistryState {
                param($Path, $Name, $State)
                @(Get-ChildItem -LiteralPath $script:backupDirectory -Filter 'local-*.json').Count | Should -Be 1
                $script:memoryRegistry["$Path|$Name"] = $State
            }
            $result = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $result.Status | Should -Be 'Configured'
            $saved = Get-Content -LiteralPath $result.SnapshotPath -Raw | ConvertFrom-Json
            $saved.Changes[0].Before.ValueExists | Should -BeFalse
            $saved.Context.MachineId | Should -Be 'test-machine'
        }

        It 'does not mutate when saving recovery state fails' {
            Mock Write-GpoJson { throw 'Recovery disk is full.' }
            { Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false } | Should -Throw '*disk is full*'
            Should -Invoke Set-GpoRegistryState -Times 0 -Exactly
        }

        It 'does not repeat changes when configuration already matches' {
            $first = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $second = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $second.Status | Should -Be 'Unchanged'
            $second.SnapshotPath | Should -BeNullOrEmpty
            Should -Invoke Set-GpoRegistryState -Times 1 -Exactly
        }

        It 'restores original absence and preserves unrelated values' {
            $script:memoryRegistry['unrelated|value'] = [pscustomobject]@{ValueExists=$true; Type='String'; Value='preserve'}
            $apply = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $restore = Restore-GpoLocalState -Path $apply.SnapshotPath -Confirm:$false
            $restore.Status | Should -Be 'Restored'
            $script:memoryRegistry[$script:testKey].ValueExists | Should -BeFalse
            $script:memoryRegistry['unrelated|value'].Value | Should -Be 'preserve'
        }

        It 'restores an existing value with its original type' {
            $script:memoryRegistry[$script:testKey] = [pscustomobject]@{KeyExists=$true; ValueExists=$true; Type='ExpandString'; Value='%OriginalValue%'}
            $apply = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $null = Restore-GpoLocalState -Path $apply.SnapshotPath -Confirm:$false
            $script:memoryRegistry[$script:testKey].Type | Should -Be 'ExpandString'
            $script:memoryRegistry[$script:testKey].Value | Should -Be '%OriginalValue%'
        }

        It 'refuses recovery on another machine' {
            $apply = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            Mock Get-GpoTargetContext { [pscustomobject]@{MachineId='another-machine'; ComputerName='OTHER'; Build=20348; Role='MemberServer'} }
            { Restore-GpoLocalState -Path $apply.SnapshotPath -Confirm:$false } | Should -Throw '*different server*'
            Should -Invoke Set-GpoRegistryState -Times 1 -Exactly
        }

        It 'refuses to overwrite a value changed after apply' {
            $apply = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $script:memoryRegistry[$script:testKey] = [pscustomobject]@{KeyExists=$true; ValueExists=$true; Type='DWord'; Value=99}
            { Restore-GpoLocalState -Path $apply.SnapshotPath -Confirm:$false } | Should -Throw '*changed after apply*'
        }

        It 'rejects a recovery path outside the selected control' {
            $apply = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $snapshot = Get-Content -LiteralPath $apply.SnapshotPath -Raw | ConvertFrom-Json
            $snapshot.Changes[0].Path = 'HKLM:\SOFTWARE\Unrelated'
            $badPath = Join-Path $script:backupDirectory 'invalid.json'
            Write-GpoJson -InputObject $snapshot -Path $badPath
            { Restore-GpoLocalState -Path $badPath -Confirm:$false } | Should -Throw '*outside its control*'
        }

        It 'preserves a recovery file after a failed write' {
            Mock Set-GpoRegistryState { throw 'A simulated write failed.' }
            { Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false } | Should -Throw '*Recovery record*'
            @(Get-ChildItem -LiteralPath $script:backupDirectory -Filter 'local-*.json').Count | Should -Be 1
        }

        It 'does not report success after failed readback' {
            Mock Set-GpoRegistryState {}
            { Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false } | Should -Throw '*Verification failed*'
        }

        It 'treats a missing optional feature as compliant' {
            Mock Get-GpoFeatureState { 'NotPresent' }
            (Get-GpoAssessment -Id PowerShell2Disabled).Status | Should -Be 'Compliant'
            Should -Invoke Set-GpoFeatureState -Times 0 -Exactly
        }

        It 'reports failed feature discovery as an error' {
            Mock Get-GpoFeatureState { throw 'Feature discovery failed.' }
            (Get-GpoAssessment -Id PowerShell2Disabled).Status | Should -Be 'Error'
        }

        It 'refuses changes while feature servicing is pending' {
            Mock Get-GpoFeatureState { 'DisablePending' }
            { Invoke-GpoLocalApply -Id PowerShell2Disabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false } | Should -Throw '*Complete servicing*'
            Should -Invoke Set-GpoFeatureState -Times 0 -Exactly
        }

        It 'keeps null and single item arrays distinct during comparison' {
            Test-GpoValuesEqual -Left @('one') -Right 'one' | Should -BeFalse
            Test-GpoValuesEqual -Left $null -Right @() | Should -BeFalse
        }

        It 'rejects an invalid saved value before any recovery write' {
            $script:memoryRegistry[$script:testKey] = [pscustomobject]@{KeyExists=$true; ValueExists=$true; Type='DWord'; Value=1}
            $apply = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $snapshot = Get-Content -LiteralPath $apply.SnapshotPath -Raw | ConvertFrom-Json
            $snapshot.Changes[0].Before.Value = 'invalid-number'
            $invalidPath = Join-Path $script:backupDirectory 'invalid-value.json'
            Write-GpoJson -InputObject $snapshot -Path $invalidPath
            { Restore-GpoLocalState -Path $invalidPath -Confirm:$false } | Should -Throw '*invalid DWORD*'
            Should -Invoke Set-GpoRegistryState -Times 1 -Exactly
        }

        It 'does not write settings or records during recovery WhatIf' {
            $apply = Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $before = @(Get-ChildItem -LiteralPath $script:backupDirectory).Count
            (Restore-GpoLocalState -Path $apply.SnapshotPath -WhatIf).Status | Should -Be 'Planned'
            @(Get-ChildItem -LiteralPath $script:backupDirectory).Count | Should -Be $before
            Should -Invoke Set-GpoRegistryState -Times 1 -Exactly
        }

        It 'restores a parent feature before its child' {
            $script:featureState = @{}
            $featureControl = Get-GpoControl -Id PowerShell2Disabled
            foreach ($name in $featureControl.Features) { $script:featureState[$name] = 'Enabled' }
            Mock Get-GpoFeatureState { param($Name) $script:featureState[$Name] }
            Mock Set-GpoFeatureState {
                param($Name, $State)
                if ($State -eq 'Enabled' -and $Name -notlike '*Root' -and $script:featureState['MicrosoftWindowsPowerShellV2Root'] -eq 'Disabled') {
                    throw 'The parent feature is disabled.'
                }
                $script:featureState[$Name] = $State
            }
            $apply = Invoke-GpoLocalApply -Id PowerShell2Disabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            (Restore-GpoLocalState -Path $apply.SnapshotPath -Confirm:$false).Status | Should -Be 'Restored'
            @($script:featureState.Values | Where-Object { $_ -ne 'Enabled' }).Count | Should -Be 0
        }

        It 'returns a restart requirement for pending feature changes' {
            $script:featureState = @{}
            foreach ($name in (Get-GpoControl -Id PowerShell2Disabled).Features) { $script:featureState[$name] = 'Enabled' }
            Mock Get-GpoFeatureState { param($Name) $script:featureState[$Name] }
            Mock Set-GpoFeatureState { param($Name, $State) $script:featureState[$Name] = 'DisablePending' }
            $apply = Invoke-GpoLocalApply -Id PowerShell2Disabled -BackupDirectory $script:backupDirectory -AcceptCompatibilityRisk -Confirm:$false
            $apply.RestartRequired | Should -BeTrue
            { Restore-GpoLocalState -Path $apply.SnapshotPath -Confirm:$false } | Should -Throw '*completed servicing*'
        }
    }
}
