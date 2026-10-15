BeforeAll {
    $script:repositoryRoot = Split-Path -Parent $PSScriptRoot
    $script:catalogue = Import-PowerShellDataFile (Join-Path $script:repositoryRoot 'PowerShell/GPOScripts/Data/Controls.psd1')
    $script:localRoot = Join-Path $script:repositoryRoot 'PowerShell/Local System'
    $script:groupRoot = Join-Path $script:repositoryRoot 'PowerShell/Group Policy'
    $script:startupPath = Join-Path $script:groupRoot 'Startup Scripts/Startup-Disable-PowerShellv2.ps1'

    # These substitutes keep wrapper tests independent from every administrative provider.
    function Get-GpoControl { [CmdletBinding()] param([string[]]$Id) }
    function Get-GpoAssessment { [CmdletBinding()] param([string[]]$Id) }
    function Invoke-GpoLocalApply {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param([string[]]$Id, [string]$BackupDirectory, [switch]$AcceptCompatibilityRisk)
    }
    function Restore-GpoLocalState {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param([string]$Path)
    }
    function New-GpoConfiguration {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [string]$Name, [string[]]$Id, [string]$Domain, [string]$Server,
            [string]$TargetVersion, [string]$Role, [string]$BackupDirectory,
            [switch]$UpdateExisting, [switch]$AcceptCompatibilityRisk
        )
    }
}

Describe 'Security control catalogue' {
    It 'uses unique IDs and complete applicability metadata' {
        $script:catalogue.SchemaVersion | Should -Be 1
        $ids = @($script:catalogue.Controls | ForEach-Object { $_.Id })
        @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        foreach ($control in $script:catalogue.Controls) {
            $control.Id | Should -Match '^[A-Za-z][A-Za-z0-9]+$'
            $control.Title | Should -Not -BeNullOrEmpty
            $control.Description | Should -Not -BeNullOrEmpty
            $control.Kind | Should -BeIn @('Registry', 'Feature', 'Audit')
            $control.MinBuild | Should -BeGreaterOrEqual 14393
            @($control.Roles).Count | Should -BeGreaterThan 0
            foreach ($role in $control.Roles) {
                $role | Should -BeIn @('MemberServer', 'DomainController')
            }
            @($control.Sources).Count | Should -BeGreaterThan 0
            foreach ($source in $control.Sources) {
                $source | Should -Match '^https://(learn|support|techcommunity)\.microsoft\.com/'
            }
        }
    }

    It 'disables old transport protocols in both connection directions' {
        foreach ($id in @('Ssl3Disabled', 'Tls10Disabled', 'Tls11Disabled')) {
            $control = $script:catalogue.Controls | Where-Object { $_.Id -eq $id }
            foreach ($direction in @('Client', 'Server')) {
                $entries = @($control.Registry | Where-Object { $_.Path.EndsWith('\' + $direction) })
                ($entries | Where-Object { $_.Name -eq 'Enabled' }).Value | Should -Be 0
                ($entries | Where-Object { $_.Name -eq 'DisabledByDefault' }).Value | Should -Be 1
                @($entries | Where-Object { $_.Type -ne 'DWord' }).Count | Should -Be 0
            }
        }
    }

    It 'preserves a supported transport protocol in both directions' {
        $control = $script:catalogue.Controls | Where-Object { $_.Id -eq 'Tls12Enabled' }
        foreach ($direction in @('Client', 'Server')) {
            $entries = @($control.Registry | Where-Object { $_.Path.EndsWith('\' + $direction) })
            ($entries | Where-Object { $_.Name -eq 'Enabled' }).Value | Should -Be 1
            ($entries | Where-Object { $_.Name -eq 'DisabledByDefault' }).Value | Should -Be 0
        }
    }

    It 'protects both framework versions and both registry views' {
        $control = $script:catalogue.Controls | Where-Object { $_.Id -eq 'DotNetSystemTls' }
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\.NETFramework', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework')) {
            foreach ($version in @('v2.0.50727', 'v4.0.30319')) {
                foreach ($name in @('SystemDefaultTlsVersions', 'SchUseStrongCrypto')) {
                    $entries = @($control.Registry | Where-Object { $_.Path -eq "$root\$version" -and $_.Name -eq $name })
                    $entries.Count | Should -Be 1
                    $entries[0].Value | Should -Be 1
                }
            }
        }
    }

    It 'uses effective SMB and anonymous account paths' {
        $smb = $script:catalogue.Controls | Where-Object { $_.Id -eq 'Smb1ServerDisabled' }
        $smb.Registry[0].Path | Should -Be 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $smb.Registry[0].Name | Should -Be 'SMB1'
        $smb.Registry[0].Value | Should -Be 0
        $sam = $script:catalogue.Controls | Where-Object { $_.Id -eq 'AnonymousSamEnumerationBlocked' }
        $sam.Registry[0].Path | Should -Be 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $sam.Registry[0].Name | Should -Be 'RestrictAnonymousSAM'
        $sam.Registry[0].Value | Should -Be 1
        $sam.Roles | Should -Not -Contain 'DomainController'
    }

    It 'requires modern SMB signing and gates outbound encryption to Server 2025' {
        $signing = $script:catalogue.Controls | Where-Object { $_.Id -eq 'SmbSigningRequired' }
        foreach ($service in @('LanmanWorkstation', 'LanmanServer')) {
            $entry = $signing.Registry | Where-Object { $_.Path -eq "HKLM:\SYSTEM\CurrentControlSet\Services\$service\Parameters" }
            $entry.Name | Should -Be 'RequireSecuritySignature'
            $entry.Value | Should -Be 1
        }
        $encryption = $script:catalogue.Controls | Where-Object { $_.Id -eq 'SmbClientEncryptionRequired' }
        $encryption.MinBuild | Should -Be 26100
        $encryption.CompatibilityRisk | Should -BeTrue
        $encryption.Registry[0].Name | Should -Be 'RequireEncryption'
        $encryption.Registry[0].Value | Should -Be 1
    }

    It 'keeps the approved Kerberos mask and refuses older NTLM responses' {
        $kerberos = $script:catalogue.Controls | Where-Object { $_.Id -eq 'KerberosAesAllowed' }
        $kerberos.Registry[0].Value | Should -Be 0x7ffffff8
        ($kerberos.Registry[0].Value -band 7) | Should -Be 0
        $ntlm = $script:catalogue.Controls | Where-Object { $_.Id -eq 'NtlmV2Only' }
        $ntlm.Registry[0].Name | Should -Be 'LmCompatibilityLevel'
        $ntlm.Registry[0].Value | Should -Be 5
    }

    It 'separates legacy LDAP signing from Server 2025 enforcement' {
        $older = $script:catalogue.Controls | Where-Object { $_.Id -eq 'LdapServerSigningRequired' }
        $newer = $script:catalogue.Controls | Where-Object { $_.Id -eq 'LdapServerSigningEnforced' }
        $older.MaxBuild | Should -Be 26099
        $newer.MinBuild | Should -Be 26100
        $older.Registry[0].Name | Should -Be 'LDAPServerIntegrity'
        $older.Registry[0].Value | Should -Be 2
        $newer.Registry[0].Name | Should -Be 'LDAPServerEnforceIntegrity'
        $newer.Registry[0].Value | Should -Be 1
        foreach ($control in @($older, $newer)) {
            $control.Roles.Count | Should -Be 1
            $control.Roles[0] | Should -Be 'DomainController'
        }
        $channel = $script:catalogue.Controls | Where-Object { $_.Id -eq 'LdapChannelBindingRequired' }
        $channel.Registry[0].Name | Should -Be 'LdapEnforceChannelBinding'
        $channel.Registry[0].Value | Should -Be 2
        $channel.Roles | Should -Not -Contain 'MemberServer'
        $client = $script:catalogue.Controls | Where-Object { $_.Id -eq 'LdapClientSigningRequired' }
        $client.Roles | Should -Contain 'MemberServer'
        $client.Roles | Should -Contain 'DomainController'
    }

    It 'limits LAPS backup to supported member servers without setting unrelated policy' {
        $control = $script:catalogue.Controls | Where-Object { $_.Id -eq 'LapsBackupToActiveDirectory' }
        $control.MinBuild | Should -Be 17763
        $control.Roles.Count | Should -Be 1
        $control.Roles[0] | Should -Be 'MemberServer'
        $control.Registry.Count | Should -Be 1
        $control.Registry[0].Path | Should -Be 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
        $control.Registry[0].Name | Should -Be 'BackupDirectory'
        $control.Registry[0].Type | Should -Be 'DWord'
        $control.Registry[0].Value | Should -Be 2
        $control.CompatibilityRisk | Should -BeTrue
        $control.Description | Should -Match 'April 11, 2023'
        $control.Description | Should -Match 'schema, permissions, encryption, password recovery'
        $control.Description | Should -Match 'cannot restore passwords'
    }

    It 'limits LSA protection without a firmware lock to Server 2025' {
        $control = $script:catalogue.Controls | Where-Object { $_.Id -eq 'LsaProtectionEnabled' }
        $control.MinBuild | Should -Be 26100
        $control.Roles | Should -Contain 'MemberServer'
        $control.Roles | Should -Contain 'DomainController'
        $control.Registry.Count | Should -Be 1
        $control.Registry[0].Path | Should -Be 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $control.Registry[0].Name | Should -Be 'RunAsPPL'
        $control.Registry[0].Type | Should -Be 'DWord'
        $control.Registry[0].Value | Should -Be 2
        $control.CompatibilityRisk | Should -BeTrue
        $control.RestartRequired | Should -BeTrue
        $control.Description | Should -Match 'Existing firmware locks'
    }

    It 'enables Windows PowerShell logging with a privacy warning' {
        $control = $script:catalogue.Controls | Where-Object { $_.Id -eq 'PowerShellScriptBlockLoggingEnabled' }
        $control.MinBuild | Should -Be 14393
        $control.Roles | Should -Contain 'MemberServer'
        $control.Roles | Should -Contain 'DomainController'
        $control.Registry.Count | Should -Be 1
        $control.Registry[0].Path | Should -Be 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        $control.Registry[0].Name | Should -Be 'EnableScriptBlockLogging'
        $control.Registry[0].Type | Should -Be 'DWord'
        $control.Registry[0].Value | Should -Be 1
        $control.CompatibilityRisk | Should -BeTrue
        $control.Description | Should -Match 'sensitive data'
        $control.Description | Should -Match 'PowerShell 7 requires separate'
    }

    It 'enables each current firewall profile without changing its rules' {
        $control = $script:catalogue.Controls | Where-Object { $_.Id -eq 'FirewallEnabled' }
        $control.MinBuild | Should -Be 14393
        $control.Roles | Should -Contain 'MemberServer'
        $control.Roles | Should -Contain 'DomainController'
        $control.Registry.Count | Should -Be 3
        foreach ($profile in @('DomainProfile', 'PrivateProfile', 'PublicProfile')) {
            $entries = @($control.Registry | Where-Object { $_.Path -eq "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$profile" })
            $entries.Count | Should -Be 1
            $entries[0].Name | Should -Be 'EnableFirewall'
            $entries[0].Type | Should -Be 'DWord'
            $entries[0].Value | Should -Be 1
        }
        $control.CompatibilityRisk | Should -BeTrue
        $control.Description | Should -Match 'allow rules'
        $control.Description | Should -Match 'console access'
    }

    It 'keeps unsupported broad changes outside the catalogue' {
        $entries = @($script:catalogue.Controls | ForEach-Object { $_.Registry })
        @($entries | Where-Object { $_.Name -in @('SMB2', 'EnableSecuritySignature', 'StrongCertificateBindingEnforcement', 'CertificateBackdatingCompensation', 'Functions', 'EnableMDNS', 'LsaCfgFlags', 'EnableVirtualizationBasedSecurity') }).Count | Should -Be 0
        @($entries | Where-Object { $_.Path -match '\\Services\\S\\|\\CurrentControlSet\\LSA$|\\mrxsmb20' }).Count | Should -Be 0
    }

    It 'keeps readiness controls read only and feature checks explicit' {
        foreach ($id in @('KerberosReadiness', 'CertificateReadiness', 'LdapReadiness', 'NtlmReadiness', 'MdnsReadiness', 'BaselineCoverage')) {
            $control = $script:catalogue.Controls | Where-Object { $_.Id -eq $id }
            $control.Kind | Should -Be 'Audit'
            $control.ContainsKey('Registry') | Should -BeFalse
            $control.ContainsKey('Features') | Should -BeFalse
        }
        $feature = $script:catalogue.Controls | Where-Object { $_.Id -eq 'PowerShell2Disabled' }
        $feature.Kind | Should -Be 'Feature'
        $feature.Features | Should -Contain 'MicrosoftWindowsPowerShellV2'
        $feature.Features | Should -Contain 'MicrosoftWindowsPowerShellV2Root'
    }
}

Describe 'Compatibility wrappers' {
    BeforeEach {
        Mock Import-Module {}
        Mock Get-GpoControl {
            param($Id)
            $definitions = Import-PowerShellDataFile (Join-Path $PSScriptRoot '../PowerShell/GPOScripts/Data/Controls.psd1')
            @($definitions.Controls | Where-Object { $Id -contains $_.Id })
        }
        Mock Get-GpoAssessment { [pscustomobject]@{ Status = 'Assessed' } }
        Mock Invoke-GpoLocalApply { [pscustomobject]@{ Status = 'Mocked' } }
        Mock Restore-GpoLocalState { [pscustomobject]@{ Status = 'Mocked' } }
        Mock New-GpoConfiguration { [pscustomobject]@{ Status = 'Mocked' } }
    }

    It 'assesses every local set wrapper by default' {
        $files = @(Get-ChildItem -LiteralPath $script:localRoot -Filter 'Set-*.ps1')
        foreach ($file in $files) { & $file.FullName }
        Should -Invoke Get-GpoAssessment -Times $files.Count -Exactly
        Should -Invoke Invoke-GpoLocalApply -Times 0 -Exactly
        Should -Invoke New-GpoConfiguration -Times 0 -Exactly
    }

    It 'requires a backup directory before local changes' {
        { & (Join-Path $script:localRoot 'Set-DisableSMB1.0.ps1') -Apply } | Should -Throw '*BackupDirectory*'
        Should -Invoke Invoke-GpoLocalApply -Times 0 -Exactly
    }

    It 'forwards explicit change and preview flags to the shared API' {
        & (Join-Path $script:localRoot 'Set-DisableSMB1.0.ps1') -Apply -BackupDirectory 'TestDrive:\backups' -AcceptCompatibilityRisk -WhatIf -Confirm:$false
        Should -Invoke Invoke-GpoLocalApply -Times 1 -Exactly -ParameterFilter {
            $Id.Count -eq 1 -and $Id[0] -eq 'Smb1ServerDisabled' -and
            $BackupDirectory -eq 'TestDrive:\backups' -and $AcceptCompatibilityRisk -and $WhatIf -and -not $Confirm
        }
    }

    It 'requires a recorded snapshot for every rollback wrapper' {
        $files = @(Get-ChildItem -LiteralPath $script:localRoot -Filter 'Rollback-*.ps1')
        foreach ($file in $files) {
            { & $file.FullName } | Should -Throw '*recorded snapshot*'
        }
        Should -Invoke Restore-GpoLocalState -Times 0 -Exactly
    }

    It 'delegates rollback without inventing insecure settings' {
        & (Join-Path $script:localRoot 'Rollback-DisableSMB1.0.ps1') -Path 'TestDrive:\snapshot.json' -WhatIf -Confirm:$false
        Should -Invoke Restore-GpoLocalState -Times 1 -Exactly -ParameterFilter {
            $Path -eq 'TestDrive:\snapshot.json' -and $WhatIf -and -not $Confirm
        }
        Should -Invoke Invoke-GpoLocalApply -Times 0 -Exactly
    }

    It 'shows definitions from every standard create wrapper by default' {
        $files = @(Get-ChildItem -LiteralPath $script:groupRoot -Filter 'Create-*.ps1' |
            Where-Object { $_.Name -ne 'Create-KDCStrongEnforcementGPOs.ps1' })
        foreach ($file in $files) { & $file.FullName }
        Should -Invoke Get-GpoControl -Times $files.Count -Exactly
        Should -Invoke New-GpoConfiguration -Times 0 -Exactly
    }

    It 'requires all destination fields before creating a policy object' {
        { & (Join-Path $script:groupRoot 'Create-SMBGPOs.ps1') -Create } | Should -Throw '*requires -Name*'
        Should -Invoke New-GpoConfiguration -Times 0 -Exactly
    }

    It 'excludes outbound encryption from a Server 2022 policy' {
        @(Get-GpoControl -Id 'Smb1ServerDisabled').Count | Should -Be 1
        & (Join-Path $script:groupRoot 'Create-SMBGPOs.ps1') -Create -Name 'Test policy' -Domain 'example.test' -Server 'dc.example.test' -Role MemberServer -TargetVersion 2022 -BackupDirectory 'TestDrive:\backups' -AcceptCompatibilityRisk -WhatIf -Confirm:$false
        Should -Invoke New-GpoConfiguration -Times 1 -Exactly -ParameterFilter {
            $Id -contains 'Smb1ServerDisabled' -and $Id -contains 'SmbSigningRequired' -and
            $Id -notcontains 'SmbClientEncryptionRequired' -and $WhatIf -and -not $Confirm
        }
    }

    It 'selects Server 2025 directory enforcement for a domain controller' {
        & (Join-Path $script:groupRoot 'Create-LDAPGPOs.ps1') -Create -Name 'Test policy' -Domain 'example.test' -Server 'dc.example.test' -Role DomainController -TargetVersion 2025 -BackupDirectory 'TestDrive:\backups' -WhatIf -Confirm:$false
        Should -Invoke New-GpoConfiguration -Times 1 -Exactly -ParameterFilter {
            $Id -contains 'LdapServerSigningEnforced' -and $Id -contains 'LdapChannelBindingRequired' -and
            $Id -notcontains 'LdapServerSigningRequired'
        }
    }

    It 'creates only client directory settings for member servers' {
        & (Join-Path $script:groupRoot 'Create-LDAPGPOs.ps1') -Create -Name 'Test policy' -Domain 'example.test' -Server 'dc.example.test' -Role MemberServer -TargetVersion 2022 -BackupDirectory 'TestDrive:\backups' -WhatIf -Confirm:$false
        Should -Invoke New-GpoConfiguration -Times 1 -Exactly -ParameterFilter {
            $Id.Count -eq 1 -and $Id[0] -eq 'LdapClientSigningRequired'
        }
    }

    It 'keeps certificate and cipher wrappers read only' {
        & (Join-Path $script:groupRoot 'Create-KDCStrongEnforcementGPOs.ps1')
        & (Join-Path $script:localRoot 'Set-TLSCipherSuiteOrder.ps1')
        Should -Invoke Get-GpoAssessment -Times 1 -Exactly -ParameterFilter { $Id -contains 'CertificateReadiness' }
        Should -Invoke Get-GpoAssessment -Times 1 -Exactly -ParameterFilter { $Id -contains 'BaselineCoverage' }
        Should -Invoke Invoke-GpoLocalApply -Times 0 -Exactly
        Should -Invoke New-GpoConfiguration -Times 0 -Exactly
    }

    It 'keeps startup execution read only by default' {
        & $script:startupPath
        Should -Invoke Get-GpoAssessment -Times 1 -Exactly -ParameterFilter { $Id -contains 'PowerShell2Disabled' }
        Should -Invoke Invoke-GpoLocalApply -Times 0 -Exactly
    }

    It 'suppresses prompts for an explicit startup change' {
        & $script:startupPath -Apply -BackupDirectory 'TestDrive:\backups' -AcceptCompatibilityRisk -WhatIf
        Should -Invoke Invoke-GpoLocalApply -Times 1 -Exactly -ParameterFilter {
            $Id -contains 'PowerShell2Disabled' -and $AcceptCompatibilityRisk -and $WhatIf -and -not $Confirm
        }
        { & $script:startupPath -Apply -BackupDirectory 'TestDrive:\backups' -Confirm } | Should -Throw '*confirmation prompts*'
    }

    It 'contains no direct administrative operations in compatibility wrappers' {
        $files = @(Get-ChildItem -LiteralPath $script:localRoot -Filter '*.ps1')
        $files += @(Get-ChildItem -LiteralPath $script:groupRoot -Filter '*.ps1' -Recurse)
        $forbidden = @(
            'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'New-Item', 'Remove-Item',
            'New-GPO', 'Set-GPPrefRegistryValue', 'Set-GPRegistryValue', 'New-GPLink',
            'Restart-Computer', 'shutdown', 'dism.exe', 'Disable-WindowsOptionalFeature', 'Read-Host'
        )
        foreach ($file in $files) {
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0
            $commands = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true)
            foreach ($command in $commands) {
                $command.GetCommandName() | Should -Not -BeIn $forbidden
            }
        }
    }
}
