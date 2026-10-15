BeforeAll {
    . (Join-Path $PSScriptRoot '../PowerShell/GPOScripts/Private/Readiness.ps1')
    function New-GpoResult {
        param($Control, $Status, $Reason, $Evidence)
        [pscustomobject]@{ ControlId = $Control.Id; Status = $Status; Reason = $Reason; Evidence = $Evidence }
    }
    # Test-local stubs prevent any fallback to a live administrative provider.
    function Get-WinEvent { [CmdletBinding()]param($ListLog, $FilterHashtable, $MaxEvents) throw 'Unmocked event provider.' }
    function Get-Item { [CmdletBinding()]param($LiteralPath) throw 'Unmocked registry provider.' }
    function Get-CimInstance { [CmdletBinding()]param($Namespace, $ClassName) throw 'Unmocked device provider.' }
    function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore) throw 'Unmocked firewall provider.' }
    function Get-MpComputerStatus { [CmdletBinding()]param() throw 'Unmocked antivirus provider.' }
    function Get-NetUDPEndpoint { [CmdletBinding()]param($LocalPort) throw 'Unmocked endpoint provider.' }
    function New-TestReadinessEvent {
        param([int]$Id, [string]$Provider = 'Microsoft-Windows-Security-Auditing', [string]$Xml = '<Event><EventData /></Event>')
        $item = [pscustomobject]@{ Id = $Id; ProviderName = $Provider; Message = 'PRIVATE_ACCOUNT_AND_FULL_EVENT_TEXT'; Xml = $Xml }
        $item | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
        $item
    }
}

Describe 'Readiness control results' {
    BeforeEach {
        $context = [pscustomobject]@{ Version = 2025; Build = 26100; Role = 'DomainController' }
        Mock Get-GpoReadinessRegistryEvidence { [pscustomobject]@{ Path = $Path; Name = $Name; State = 'NotConfigured'; Value = $null; Type = $null } }
        Mock Get-GpoReadinessEventEvidence { [pscustomobject]@{ State = 'NoMatchingEvents'; ReturnedEvents = 0; Counts = @{} } }
        Mock Get-GpoReadinessDeviceGuardEvidence { [pscustomobject]@{ State = 'Unavailable'; CredentialGuardRunning = $null } }
        Mock Get-GpoReadinessBaselineEvidence { [pscustomobject]@{ State = 'Unavailable' } }
        Mock Get-NetUDPEndpoint { @() }
    }

    It 'does not infer readiness from empty evidence for <Id>' -TestCases @(
        @{ Id = 'KerberosReadiness' }, @{ Id = 'CertificateReadiness' }, @{ Id = 'LdapReadiness' },
        @{ Id = 'NtlmReadiness' }, @{ Id = 'MdnsReadiness' }, @{ Id = 'BaselineCoverage' }
    ) {
        param($Id)
        $result = Invoke-GpoReadinessCheck -Control ([pscustomobject]@{ Id = $Id }) -Context $context
        $result.Status | Should -Be 'ReviewRequired'
        $result.Evidence.Scope | Should -Be 'Local computer only'
    }

    It 'does not query domain controller events from a member server' {
        $context.Role = 'MemberServer'
        foreach ($id in @('KerberosReadiness', 'CertificateReadiness', 'LdapReadiness')) {
            $result = Invoke-GpoReadinessCheck -Control ([pscustomobject]@{ Id = $id }) -Context $context
            $result.Evidence.Limitations.Count | Should -BeGreaterThan 2
        }
        Should -Invoke Get-GpoReadinessEventEvidence -Times 0 -Exactly
    }

    It 'reports read errors without a compliant result' {
        Mock Get-GpoReadinessEventEvidence { [pscustomobject]@{ State = 'ReadError'; ReturnedEvents = 0 } }
        $result = Invoke-GpoReadinessCheck -Control ([pscustomobject]@{ Id = 'KerberosReadiness' }) -Context $context
        $result.Status | Should -Be 'ReviewRequired'
        @($result.Evidence.Events | Where-Object State -eq 'ReadError').Count | Should -Be 2
    }

    It 'includes both LDAP signing controls and the channel binding control' {
        $result = Invoke-GpoReadinessCheck -Control ([pscustomobject]@{ Id = 'LdapReadiness' }) -Context $context
        $result.Evidence.Policy.Name | Should -Contain 'LDAPServerIntegrity'
        $result.Evidence.Policy.Name | Should -Contain 'LDAPServerEnforceIntegrity'
        $result.Evidence.Policy.Name | Should -Contain 'LdapEnforceChannelBinding'
    }

    It 'preserves unavailable endpoint evidence without inventing zero listeners' {
        Mock Get-NetUDPEndpoint { throw 'Access denied. PRIVATE_ACCOUNT' }
        $result = Invoke-GpoReadinessCheck -Control ([pscustomobject]@{ Id = 'MdnsReadiness' }) -Context $context
        $result.Evidence.Listeners.State | Should -Be 'Unavailable'
        $result.Evidence.Listeners.Udp5353Endpoints | Should -BeNullOrEmpty
        ($result | ConvertTo-Json -Depth 15) | Should -Not -Match 'PRIVATE_ACCOUNT'
    }

    It 'counts listeners without exporting addresses or process identifiers' {
        Mock Get-NetUDPEndpoint { @([pscustomobject]@{ OwningProcess = 12; LocalAddress = '192.0.2.10' }, [pscustomobject]@{ OwningProcess = 12; LocalAddress = '::' }) }
        $result = Invoke-GpoReadinessCheck -Control ([pscustomobject]@{ Id = 'MdnsReadiness' }) -Context $context
        $result.Evidence.Listeners.Udp5353Endpoints | Should -Be 2
        $result.Evidence.Listeners.ProcessCount | Should -Be 1
        ($result.Evidence.Listeners | ConvertTo-Json) | Should -Not -Match 'OwningProcess|LocalAddress|192.0.2.10'
    }

    It 'fails explicitly for an unknown audit control' {
        (Invoke-GpoReadinessCheck -Control ([pscustomobject]@{ Id = 'UnknownReadiness' }) -Context $context).Status | Should -Be 'Error'
    }
}

Describe 'Bounded event collection' {
    BeforeEach {
        Mock Get-GpoReadinessLogEvidence { [pscustomobject]@{ State = 'Enabled'; LogName = $LogName } }
        Mock Get-WinEvent { @() }
    }

    It 'passes a time window and a strict event cap' {
        $result = Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4768, 4769) -MaxEvents 2
        $result.State | Should -Be 'NoMatchingEvents'
        Should -Invoke Get-WinEvent -Times 1 -Exactly -ParameterFilter {
            $MaxEvents -eq 2 -and $FilterHashtable.LogName -eq 'Security' -and
            $FilterHashtable.Id.Count -eq 2 -and
            ($FilterHashtable.EndTime - $FilterHashtable.StartTime).TotalDays -eq 7
        }
    }

    It 'marks a full sample as potentially incomplete' {
        Mock Get-WinEvent { @(New-TestReadinessEvent -Id 4768; New-TestReadinessEvent -Id 4769) }
        $result = Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4768, 4769) -MaxEvents 2
        $result.SampleMayBeTruncated | Should -BeTrue
        $result.Counts['4768'] | Should -Be 1
        $result.Counts['4769'] | Should -Be 1
    }

    It 'filters unrelated providers after the bounded read' {
        Mock Get-WinEvent { @(New-TestReadinessEvent -Id 39 -Provider 'OtherProvider'; New-TestReadinessEvent -Id 39 -Provider 'Kdcsvc') }
        $result = Get-GpoReadinessEventEvidence -LogName 'System' -Id @(39) -ProviderName @('Kdcsvc')
        $result.ReturnedEvents | Should -Be 2
        $result.IncludedEvents | Should -Be 1
        $result.Counts['39'] | Should -Be 1
    }

    It 'exports counts without account names or raw event payloads' {
        Mock Get-WinEvent {
            New-TestReadinessEvent -Id 4769 -Xml '<Event><EventData><Data Name="TargetUserName">PRIVATE_ACCOUNT</Data><Data Name="TicketEncryptionType">0x17</Data><Data Name="SessionKeyEncryptionType">0x12</Data></EventData></Event>'
        }
        $result = Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4769) -KerberosEncryption
        $result.Encryption.Rc4Fields | Should -Be 1
        $result.Encryption.AesFields | Should -Be 1
        ($result | ConvertTo-Json -Depth 15) | Should -Not -Match 'PRIVATE_ACCOUNT|TargetUserName|<Event>|FULL_EVENT_TEXT'
    }

    It 'records malformed encryption evidence without claiming success' {
        Mock Get-WinEvent { New-TestReadinessEvent -Id 4769 -Xml 'malformed' }
        $result = Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4769) -KerberosEncryption
        $result.Encryption.ParseErrors | Should -Be 1
        $result.Encryption.Rc4Fields | Should -Be 0
    }

    It 'rejects XML document type declarations without resolving entities' {
        Mock Get-WinEvent { New-TestReadinessEvent -Id 4769 -Xml '<!DOCTYPE Event [<!ENTITY payload SYSTEM "file:///nonexistent">]><Event><EventData><Data Name="TicketEncryptionType">&payload;</Data></EventData></Event>' }
        $result = Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4769) -KerberosEncryption
        $result.Encryption.ParseErrors | Should -Be 1
    }

    It 'marks missing encryption fields as incomplete evidence' {
        Mock Get-WinEvent { New-TestReadinessEvent -Id 4769 }
        $result = Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4769) -KerberosEncryption
        $result.Encryption.MissingFields | Should -Be 1
    }

    It 'does not query events when the log is disabled' {
        Mock Get-GpoReadinessLogEvidence { [pscustomobject]@{ State = 'Disabled'; LogName = $LogName } }
        $result = Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4769)
        $result.State | Should -Be 'Unavailable'
        Should -Invoke Get-WinEvent -Times 0 -Exactly
    }

    It 'distinguishes access failure from an empty sample' {
        Mock Get-WinEvent { throw 'Access denied. PRIVATE_ACCOUNT' }
        $result = Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4769)
        $result.State | Should -Be 'ReadError'
        ($result | ConvertTo-Json -Depth 15) | Should -Not -Match 'PRIVATE_ACCOUNT'
    }

    It 'recognizes the provider error for no matching events' {
        Mock Get-WinEvent {
            $errorRecord = New-Object System.Management.Automation.ErrorRecord([System.Exception]::new('No events'), 'NoMatchingEventsFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
            throw $errorRecord
        }
        (Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4769)).State | Should -Be 'NoMatchingEvents'
    }
}

Describe 'Registry evidence privacy and failure handling' {
    It 'does not treat denied access as an absent setting' {
        Mock Get-Item { throw [System.UnauthorizedAccessException]::new('Private details') }
        $result = Get-GpoReadinessRegistryEvidence -Path 'HKLM:\Example' -Name 'Setting'
        $result.State | Should -Be 'ReadError'
        ($result | ConvertTo-Json) | Should -Not -Match 'Private details'
    }

    It 'reports a missing key without assuming an effective default' {
        Mock Get-Item { throw [System.Management.Automation.ItemNotFoundException]::new('Missing key') }
        $result = Get-GpoReadinessRegistryEvidence -Path 'HKLM:\Example' -Name 'Setting'
        $result.State | Should -Be 'NotConfigured'
        $result.Value | Should -BeNullOrEmpty
    }

    It 'exports only DWORD values from known policy names' {
        Mock Get-Item {
            $key = [pscustomobject]@{}
            $key | Add-Member ScriptMethod GetValueNames { @('Setting') }
            $key | Add-Member ScriptMethod GetValueKind { 'String' }
            $key | Add-Member ScriptMethod GetValue { 'PRIVATE_ACCOUNT' }
            $key
        }
        $result = Get-GpoReadinessRegistryEvidence -Path 'HKLM:\Example' -Name 'Setting'
        $result.State | Should -Be 'UnexpectedType'
        ($result | ConvertTo-Json) | Should -Not -Match 'PRIVATE_ACCOUNT'
    }
}

Describe 'Baseline coverage advice' {
    BeforeEach {
        Mock Get-NetFirewallProfile { throw 'Unavailable' }
        Mock Get-MpComputerStatus { throw 'Unavailable' }
        Mock Get-CimInstance { throw 'Unavailable' }
        Mock Get-GpoReadinessRegistryEvidence { [pscustomobject]@{ State = 'NotConfigured'; Value = $null } }
        Mock Get-GpoReadinessLogEvidence { [pscustomobject]@{ State = 'Unavailable' } }
    }

    It 'does not claim Windows LAPS eligibility on Server 2016' {
        $result = Get-GpoReadinessBaselineEvidence -Context ([pscustomobject]@{ Version = 2016; Role = 'MemberServer' })
        $result.WindowsLaps.PlatformEligible | Should -BeFalse
        $result.WindowsLaps.State | Should -Be 'ReviewRequired'
    }

    It 'separates Server 2025 eligibility from completed password management' {
        $result = Get-GpoReadinessBaselineEvidence -Context ([pscustomobject]@{ Version = 2025; Role = 'DomainController' })
        $result.WindowsLaps.PlatformEligible | Should -BeTrue
        $result.WindowsLaps.State | Should -Be 'ReviewRequired'
        $result.WindowsLaps.Purpose | Should -Be 'Recovery account password management'
    }

    It 'keeps missing protection evidence unavailable' {
        $result = Get-GpoReadinessBaselineEvidence -Context ([pscustomobject]@{ Version = 2022; Role = 'MemberServer' })
        $result.Firewall.State | Should -Be 'Unavailable'
        $result.Defender.State | Should -Be 'Unavailable'
        $result.CredentialProtection.State | Should -Be 'Unavailable'
        $result.CredentialProtection.CredentialGuardRunning | Should -BeNullOrEmpty
    }

    It 'reads effective firewall profiles from the active policy store' {
        Mock Get-NetFirewallProfile { [pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow' } }
        $result = Get-GpoReadinessBaselineEvidence -Context ([pscustomobject]@{ Version = 2022; Role = 'MemberServer' })
        $result.Firewall.State | Should -Be 'Observed'
        $result.Firewall.Profiles[0].Enabled | Should -Be 'True'
        Should -Invoke Get-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { $PolicyStore -eq 'ActiveStore' }
    }
}
