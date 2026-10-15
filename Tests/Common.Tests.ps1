BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../PowerShell/GPOScripts/GPOScripts.psd1') -Force
}
Describe 'Target detection and control validation' {
    InModuleScope GPOScripts {
        BeforeEach {
            Mock Get-GpoRegistryState { [pscustomobject]@{ValueExists=$true; Value='test-machine'} }
        }
        It 'rejects unknown controls before a provider runs' {
            { Get-GpoControl -Id 'NotAControl' } | Should -Throw '*Unknown control*'
        }
        It 'rejects an empty explicit selection' {
            { Get-GpoControl -Id @() } | Should -Throw '*Select at least one*'
        }
        It 'recognizes Server 2022 member servers' {
            Mock Get-CimInstance { [pscustomobject]@{BuildNumber='20348'; ProductType=3; CSName='LAB'} }
            $context = Get-GpoTargetContext
            $context.Version | Should -Be '2022'
            $context.Role | Should -Be 'MemberServer'
            $context.Supported | Should -BeTrue
        }
        It 'recognizes Server 2025 domain controllers' {
            Mock Get-CimInstance { [pscustomobject]@{BuildNumber='26100'; ProductType=2; CSName='LAB'} }
            $context = Get-GpoTargetContext
            $context.Version | Should -Be '2025'
            $context.Role | Should -Be 'DomainController'
            $context.Supported | Should -BeTrue
        }
        It 'rejects Windows clients with a shared server build' {
            Mock Get-CimInstance { [pscustomobject]@{BuildNumber='26100'; ProductType=1; CSName='LAB'} }
            (Get-GpoTargetContext).Supported | Should -BeFalse
        }
        It 'rejects an unsupported server build' {
            Mock Get-CimInstance { [pscustomobject]@{BuildNumber='9600'; ProductType=3; CSName='LAB'} }
            (Get-GpoTargetContext).Supported | Should -BeFalse
        }
        It 'does not substitute a missing machine identity' {
            Mock Get-CimInstance { [pscustomobject]@{BuildNumber='20348'; ProductType=3; CSName='LAB'} }
            Mock Get-GpoRegistryState { [pscustomobject]@{ValueExists=$false; Value=$null} }
            { Get-GpoTargetContext } | Should -Throw '*machine identifier*'
        }
        It 'enforces the maximum build for older LDAP signing' {
            $context = [pscustomobject]@{Build=26100; Role='DomainController'; Supported=$true}
            (Test-GpoControlApplicability -Control (Get-GpoControl -Id LdapServerSigningRequired) -Context $context).Applicable | Should -BeFalse
        }
        It 'preserves an existing JSON record' {
            $path = Join-Path $TestDrive 'existing.json'
            Write-GpoJson -InputObject @{Value='original'} -Path $path
            { Write-GpoJson -InputObject @{Value='replacement'} -Path $path } | Should -Throw
            (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).Value | Should -Be 'original'
        }
    }
}
