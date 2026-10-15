BeforeAll {
    $providerRoot = Join-Path $PSScriptRoot '../PowerShell/GPOScripts/Private'
    . (Join-Path $providerRoot 'Common.ps1')
    . (Join-Path $providerRoot 'GroupPolicy.ps1')

    # Stubs prevent accidental calls to a real domain, including on an administrator's computer.
    function Get-GPO { [CmdletBinding()] param([switch]$All, [guid]$Guid, [string]$Domain, [string]$Server) throw 'Unmocked Get-GPO.' }
    function New-GPO { [CmdletBinding()] param([string]$Name, [string]$Domain, [string]$Server, [string]$Comment) throw 'Unmocked New-GPO.' }
    function Backup-GPO { [CmdletBinding()] param([guid]$Guid, [string]$Domain, [string]$Server, [string]$Path, [string]$Comment) throw 'Unmocked Backup-GPO.' }
    function Restore-GPO { [CmdletBinding()] param([guid]$BackupId, [string]$Path, [string]$Domain, [string]$Server) throw 'Unmocked Restore-GPO.' }
    function Get-GPOReport { [CmdletBinding()] param([guid]$Guid, [string]$Domain, [string]$Server, [string]$ReportType) throw 'Unmocked Get-GPOReport.' }
    function Set-GPRegistryValue { [CmdletBinding()] param([guid]$Guid, [string]$Domain, [string]$Server, [string]$Key, [string]$ValueName, [string]$Type, $Value) throw 'Unmocked Set-GPRegistryValue.' }
    function Get-GPRegistryValue { [CmdletBinding()] param([guid]$Guid, [string]$Domain, [string]$Server, [string]$Key, [string]$ValueName) throw 'Unmocked Get-GPRegistryValue.' }
}

Describe 'Unlinked Group Policy configuration' {
    BeforeEach {
        $script:gpId = [guid]'11111111-1111-4111-8111-111111111111'
        $script:backupId = [guid]'22222222-2222-4222-8222-222222222222'
        $script:ownerId = '33333333-3333-4333-8333-333333333333'
        $script:gpExists = $false
        $script:gpLinked = $false
        $script:gpPhase = 'before'
        $script:gpPermissions = 'D:P(A;;GA;;;DA)'
        $script:gpFilterName = ''
        $script:gpCalls = New-Object 'System.Collections.Generic.List[string]'
        $script:gpOwner = [ordered]@{ SchemaVersion = 1; Product = 'GPOScripts'; OwnershipId = $script:ownerId; Domain = 'example.test'; Name = 'Test configuration'; TargetVersion = '2025'; Role = 'MemberServer' }
        $script:gpObject = [pscustomobject]@{ Id = $script:gpId; DomainName = 'example.test'; DisplayName = 'Test configuration'; Description = ('GPOScripts:v1:' + ($script:gpOwner | ConvertTo-Json -Compress)) }
        $script:gpDefault = [pscustomobject]@{ Id = [guid]'44444444-4444-4444-8444-444444444444'; DomainName = 'example.test'; DisplayName = 'Default Domain Policy'; Description = '' }
        $script:gpControl = @{ Id = 'Example'; Title = 'Example'; Kind = 'Registry'; MinBuild = 14393; Roles = @('MemberServer', 'DomainController'); CompatibilityRisk = $false; Registry = @(@{ Path = 'HKLM:\SOFTWARE\Policies\Example'; Name = 'Enabled'; Type = 'DWord'; Value = 1 }) }
        $script:gpParameters = @{ Name = 'Test configuration'; Id = @('Example'); Domain = 'example.test'; Server = 'dc1.example.test'; TargetVersion = '2025'; Role = 'MemberServer'; BackupDirectory = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N').Substring(0, 8))); Confirm = $false }
        Mock Initialize-GpoGroupPolicy {}
        Mock Get-GpoSupportDate { [datetime]'2026-10-15' }
        Mock Get-GpoControl { $script:gpControl }
        Mock Get-GPO {
            if ($All) { $script:gpDefault; if ($script:gpExists) { $script:gpObject } }
            elseif ($Guid -eq $script:gpId) { $script:gpObject }
            else { throw 'Unexpected GPO identity.' }
        }
        Mock Get-GPOReport {
            $links = if ($script:gpLinked) { '<LinksTo><SOMPath>example.test/Servers</SOMPath><Enabled>true</Enabled></LinksTo>' } else { '' }
            $filter = if ($script:gpFilterName) { '<FilterName>' + $script:gpFilterName + '</FilterName><FilterDescription>A test filter</FilterDescription>' } else { '' }
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Identifier><Identifier>{' + $Guid + '}</Identifier><Domain>example.test</Domain></Identifier><Name>Test configuration</Name><ReadTime>' + [DateTime]::UtcNow.ToString('o') + '</ReadTime><SecurityDescriptor><SDDL xmlns="http://www.microsoft.com/GroupPolicy/Types/Security">' + $script:gpPermissions + '</SDDL></SecurityDescriptor><FilterDataAvailable>true</FilterDataAvailable>' + $filter + '<Computer><VersionDirectory>1</VersionDirectory><VersionSysvol>1</VersionSysvol><Enabled>true</Enabled><ExtensionData><Value>' + $script:gpPhase + '</Value></ExtensionData></Computer><User><Enabled>true</Enabled></User>' + $links + '</GPO>'
        }
        Mock New-GPO {
            $intentFiles = @(Get-ChildItem -LiteralPath $script:gpParameters.BackupDirectory -Filter intent.json -Recurse)
            if ($intentFiles.Count -ne 1) { throw 'Creation started without an intent manifest.' }
            $script:gpCalls.Add('create')
            $script:gpObject.Description = $Comment
            $script:gpExists = $true
            $script:gpObject
        }
        Mock Backup-GPO {
            $script:gpCalls.Add('backup')
            Set-Content -LiteralPath (Join-Path $Path 'backup.xml') -Value '<backup>test fixture</backup>'
            [pscustomobject]@{ Id = $script:backupId; GpoId = $script:gpId; DomainName = 'example.test' }
        }
        Mock Set-GPRegistryValue {
            $manifests = @(Get-ChildItem -LiteralPath $script:gpParameters.BackupDirectory -Filter recovery.json -Recurse)
            if ($manifests.Count -ne 1) { throw 'Registry writes started without a recovery manifest.' }
            $script:gpCalls.Add('write')
            $script:gpPhase = 'after'
        }
        Mock Get-GPRegistryValue { [pscustomobject]@{ Type = 'DWord'; Value = $(if ($script:gpPhase -eq 'before') { 0 } else { 1 }); PolicyState = 'Set'; HasValue = $true } }
        Mock Restore-GPO { $script:gpCalls.Add('restore'); $script:gpPhase = 'before' }
    }

    It 'creates no files or domain objects during WhatIf' {
        New-GpoConfiguration @gpParameters -WhatIf
        Test-Path -LiteralPath $gpParameters.BackupDirectory | Should -BeFalse
        Should -Invoke New-GPO -Times 0 -Exactly
        Should -Invoke Backup-GPO -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'rejects long recovery paths before creating files or GPOs' {
        $script:gpParameters.BackupDirectory = Join-Path $TestDrive ('x' * 170)
        { New-GpoConfiguration @gpParameters } | Should -Throw '*recovery path is too long*'
        @(Get-ChildItem -LiteralPath $TestDrive -Directory | Where-Object { $_.Name -eq ('x' * 170) }).Count | Should -Be 0
        Should -Invoke New-GPO -Times 0 -Exactly
        Should -Invoke Backup-GPO -Times 0 -Exactly
    }

    It 'creates an owned GPO with recovery records before registry writes' {
        $result = New-GpoConfiguration @gpParameters
        $result.Status | Should -Be 'ConfiguredUnlinked'
        $result.GpoId | Should -Be $gpId
        $result.Created | Should -BeTrue
        $manifest = Get-Content -LiteralPath $result.ManifestPath -Raw | ConvertFrom-Json
        $manifest.RecoveryMode | Should -Be 'ManualRetainNewGpo'
        $manifest.GpoId | Should -Be $gpId.ToString('D')
        $manifest.Settings[0].Key | Should -Be 'HKLM\SOFTWARE\Policies\Example'
        $gpObject.Description | Should -Match '^GPOScripts:v1:'
        ($gpCalls -join ',') | Should -Be 'create,write'
        Should -Invoke Set-GPRegistryValue -Times 1 -Exactly -ParameterFilter { $Guid -eq $script:gpId -and $Domain -eq 'example.test' -and $Server -eq 'dc1.example.test' }
    }

    It 'requires explicit permission to update an existing GPO' {
        $script:gpExists = $true
        { New-GpoConfiguration @gpParameters } | Should -Throw '*UpdateExisting*'
        Should -Invoke Backup-GPO -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'refuses an existing GPO without ownership metadata' {
        $script:gpExists = $true
        $script:gpObject.Description = 'Created elsewhere'
        { New-GpoConfiguration @gpParameters -UpdateExisting } | Should -Throw '*ownership*'
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'refuses a linked GPO before creating recovery files' {
        $script:gpExists = $true
        $script:gpLinked = $true
        { New-GpoConfiguration @gpParameters -UpdateExisting } | Should -Throw '*links*'
        Test-Path -LiteralPath $gpParameters.BackupDirectory | Should -BeFalse
        Should -Invoke Backup-GPO -Times 0 -Exactly
    }

    It 'refuses a different domain returned by the server' {
        $script:gpDefault.DomainName = 'other.test'
        { New-GpoConfiguration @gpParameters } | Should -Throw '*domain*'
        Should -Invoke New-GPO -Times 0 -Exactly
    }

    It 'refuses a changed role in an owned GPO' {
        $script:gpExists = $true
        $script:gpParameters.Role = 'DomainController'
        { New-GpoConfiguration @gpParameters -UpdateExisting } | Should -Throw '*target profile*'
        Should -Invoke Backup-GPO -Times 0 -Exactly
    }

    It 'rejects audit and feature controls' -TestCases @(@{ Kind = 'Audit' }, @{ Kind = 'Feature' }) {
        param($Kind)
        $script:gpControl.Kind = $Kind
        { New-GpoConfiguration @gpParameters } | Should -Throw '*cannot become a registry policy*'
        Should -Invoke Get-GPO -Times 0 -Exactly
    }

    It 'rejects controls that require a newer server build' {
        $script:gpControl.MinBuild = 26100
        $script:gpParameters.TargetVersion = '2019'
        { New-GpoConfiguration @gpParameters } | Should -Throw '*does not apply*'
        Should -Invoke Get-GPO -Times 0 -Exactly
    }

    It 'rejects targets after their recorded support dates' -TestCases @(
        @{ Version = '2016'; Date = '2027-01-13' },
        @{ Version = '2019'; Date = '2029-01-10' },
        @{ Version = '2022'; Date = '2031-10-15' },
        @{ Version = '2025'; Date = '2034-11-15' }
    ) {
        param($Version, $Date)
        $script:gpParameters.TargetVersion = $Version
        $script:gpSupportDate = [datetime]$Date
        Mock Get-GpoSupportDate { $script:gpSupportDate }
        { New-GpoConfiguration @gpParameters } | Should -Throw '*unsupported after its recorded support date*'
        Should -Invoke Get-GPO -Times 0 -Exactly
        Should -Invoke New-GPO -Times 0 -Exactly
        Should -Invoke Backup-GPO -Times 0 -Exactly
    }

    It 'permits a target on its recorded support end date' {
        $script:gpParameters.TargetVersion = '2016'
        Mock Get-GpoSupportDate { [datetime]'2027-01-12' }
        (New-GpoConfiguration @gpParameters).Status | Should -Be 'ConfiguredUnlinked'
    }

    It 'rejects controls that do not apply to the selected role' {
        $script:gpControl.Roles = @('DomainController')
        { New-GpoConfiguration @gpParameters } | Should -Throw '*does not apply*'
        Should -Invoke Get-GPO -Times 0 -Exactly
    }

    It 'requires compatibility risk acceptance before mutation' {
        $script:gpControl.CompatibilityRisk = $true
        { New-GpoConfiguration @gpParameters } | Should -Throw '*AcceptCompatibilityRisk*'
        Should -Invoke New-GPO -Times 0 -Exactly
    }

    It 'does not back up or write an existing GPO during WhatIf' {
        $script:gpExists = $true
        New-GpoConfiguration @gpParameters -UpdateExisting -WhatIf
        Test-Path -LiteralPath $gpParameters.BackupDirectory | Should -BeFalse
        Should -Invoke Backup-GPO -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'backs up existing settings and preserves the GPO identifier' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $result.GpoId | Should -Be $gpId
        $result.Created | Should -BeFalse
        $manifest = Get-Content -LiteralPath $result.ManifestPath -Raw | ConvertFrom-Json
        $manifest.RecoveryMode | Should -Be 'RestoreExistingBackup'
        $manifest.BackupId | Should -Be $backupId.ToString('D')
        @($manifest.BackupFiles).Count | Should -Be 1
        ($gpCalls -join ',') | Should -Be 'backup,write'
        Should -Invoke New-GPO -Times 0 -Exactly
    }

    It 'returns Unchanged without backups or files when all selected values already match' {
        $script:gpExists = $true
        $script:gpPhase = 'after'
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $result.Status | Should -Be 'Unchanged'
        $result.GpoId | Should -Be $gpId
        Test-Path -LiteralPath $gpParameters.BackupDirectory | Should -BeFalse
        Should -Invoke Backup-GPO -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'permits a missing registry value only for its specific error identity' {
        $script:gpExists = $true
        Mock Get-GPRegistryValue {
            if ($script:gpPhase -eq 'before') {
                $exception = New-Object ArgumentException('The policy value is absent.', 'valueName')
                $record = New-Object System.Management.Automation.ErrorRecord($exception, 'UnableToRetrievePolicyRegistryItem,Microsoft.GroupPolicy.Commands.GetGPRegistryValueCommand', [System.Management.Automation.ErrorCategory]::InvalidArgument, $null)
                throw $record
            }
            [pscustomobject]@{ Type = 'DWord'; Value = 1; PolicyState = 'Set'; HasValue = $true }
        }
        (New-GpoConfiguration @gpParameters -UpdateExisting).Status | Should -Be 'ConfiguredUnlinked'
        Should -Invoke Set-GPRegistryValue -Times 1 -Exactly
    }

    It 'does not treat access denial as a missing registry value' {
        $script:gpExists = $true
        Mock Get-GPRegistryValue { throw (New-Object UnauthorizedAccessException('Access denied.')) }
        { New-GpoConfiguration @gpParameters -UpdateExisting } | Should -Throw '*Access denied*'
        Should -Invoke Backup-GPO -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'does not treat an unknown read error as a missing registry value' {
        $script:gpExists = $true
        Mock Get-GPRegistryValue { throw 'The server is unavailable.' }
        { New-GpoConfiguration @gpParameters -UpdateExisting } | Should -Throw '*server is unavailable*'
        Should -Invoke Backup-GPO -Times 0 -Exactly
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'stops when the backup fails' {
        $script:gpExists = $true
        Mock Backup-GPO { throw 'Backup failed.' }
        { New-GpoConfiguration @gpParameters -UpdateExisting } | Should -Throw '*Backup failed*'
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'stops when the recovery manifest cannot be saved' {
        $script:gpExists = $true
        Mock Write-GpoJson { throw 'Manifest storage failed.' }
        { New-GpoConfiguration @gpParameters -UpdateExisting } | Should -Throw '*Manifest storage failed*'
        Should -Invoke Set-GPRegistryValue -Times 0 -Exactly
    }

    It 'reports a failed readback and retains the recovery manifest' {
        Mock Get-GPRegistryValue { [pscustomobject]@{ Type = 'DWord'; Value = 0; PolicyState = 'Set'; HasValue = $true } }
        { New-GpoConfiguration @gpParameters } | Should -Throw '*Verification failed*'
        @(Get-ChildItem -LiteralPath $gpParameters.BackupDirectory -Filter recovery.json -Recurse).Count | Should -Be 1
    }

    It 'refuses automatic deletion of a new GPO' {
        $result = New-GpoConfiguration @gpParameters
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*Automatic deletion is refused*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'restores the recorded backup and verifies the previous settings' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $restored = Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false
        $restored.Status | Should -Be 'RestoredUnlinked'
        ($gpCalls -join ',') | Should -Be 'backup,write,backup,restore'
        Test-Path -LiteralPath $restored.PreservedManifestPath | Should -BeTrue
        $preserved = Get-Content -LiteralPath $restored.PreservedManifestPath -Raw | ConvertFrom-Json
        $preserved.RecoveryMode | Should -Be 'RestoreExistingBackup'
        $original = Get-Content -LiteralPath $result.ManifestPath -Raw | ConvertFrom-Json
        $preserved.PriorReportHash | Should -Not -Be $original.PriorReportHash
        Test-Path -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($restored.PreservedManifestPath)) 'completion.json') | Should -BeTrue
        Should -Invoke Restore-GPO -Times 1 -Exactly -ParameterFilter { $BackupId -eq $script:backupId -and $Domain -eq 'example.test' -and $Server -eq 'dc1.example.test' }
    }

    It 'does not write a restore record or restore a GPO during WhatIf' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $before = @(Get-ChildItem -LiteralPath $gpParameters.BackupDirectory -File -Recurse).Count
        Restore-GpoConfiguration -ManifestPath $result.ManifestPath -WhatIf
        @(Get-ChildItem -LiteralPath $gpParameters.BackupDirectory -File -Recurse).Count | Should -Be $before
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'refuses restore when the GPO acquired a link' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $script:gpLinked = $true
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*links*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'refuses restore when backup contents changed' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $manifest = Get-Content -LiteralPath $result.ManifestPath -Raw | ConvertFrom-Json
        Set-Content -LiteralPath (Join-Path $manifest.BackupPath 'backup.xml') -Value 'changed'
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*integrity verification*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'refuses restore when ownership changed' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $script:gpOwner.OwnershipId = [guid]::NewGuid().ToString('D')
        $script:gpObject.Description = 'GPOScripts:v1:' + ($script:gpOwner | ConvertTo-Json -Compress)
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*ownership*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'reports a restore readback mismatch' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        Mock Restore-GPO {}
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*settings verification failed*'
    }

    It 'does not restore when the fresh backup fails' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        Mock Backup-GPO { throw 'The fresh backup failed.' }
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*fresh backup failed*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'refuses restoration after later policy edits' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $script:gpPhase = 'later edit'
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*preserve later edits*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
        Should -Invoke Backup-GPO -Times 1 -Exactly
    }

    It 'refuses restoration after permissions change' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $script:gpPermissions = 'D:P(A;;GA;;;BA)'
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*preserve later edits*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'refuses restoration after report-visible filter metadata changes' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        $script:gpFilterName = 'A later filter'
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*preserve later edits*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'refuses automatic recovery of a partial apply without a completion record' {
        $script:gpExists = $true
        Mock Get-GPRegistryValue { [pscustomobject]@{ Type = 'DWord'; Value = 0; PolicyState = 'Set'; HasValue = $true } }
        { New-GpoConfiguration @gpParameters -UpdateExisting } | Should -Throw '*Verification failed*'
        $recovery = @(Get-ChildItem -LiteralPath $gpParameters.BackupDirectory -Filter recovery.json -Recurse)[0]
        Test-Path -LiteralPath (Join-Path $recovery.DirectoryName 'completion.json') | Should -BeFalse
        { Restore-GpoConfiguration -ManifestPath $recovery.FullName -Confirm:$false } | Should -Throw '*manual recovery*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }

    It 'refuses a recovery manifest that changed after completion' {
        $script:gpExists = $true
        $result = New-GpoConfiguration @gpParameters -UpdateExisting
        Add-Content -LiteralPath $result.ManifestPath -Value ' '
        { Restore-GpoConfiguration -ManifestPath $result.ManifestPath -Confirm:$false } | Should -Throw '*does not match the recovery manifest*'
        Should -Invoke Restore-GPO -Times 0 -Exactly
    }
}
