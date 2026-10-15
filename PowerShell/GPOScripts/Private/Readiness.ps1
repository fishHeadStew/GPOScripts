# Readiness evidence is local, bounded, and read-only. It never proves application compatibility.
function Get-GpoReadinessRegistryEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $result = [ordered]@{ Path = $Path; Name = $Name; State = 'Unavailable'; Value = $null; Type = $null }
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if (@($key.GetValueNames()) -notcontains $Name) {
            $result.State = 'NotConfigured'
        } else {
            $kind = [string]$key.GetValueKind($Name)
            $result.Type = $kind
            if ($kind -eq 'DWord') {
                $result.Value = $key.GetValue($Name)
                $result.State = 'Observed'
            } else {
                # Readiness checks request DWORD policy values only. Do not export unexpected data.
                $result.State = 'UnexpectedType'
            }
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        $result.State = 'NotConfigured'
    } catch {
        $result.State = 'ReadError'
    }
    [pscustomobject]$result
}

function Get-GpoReadinessLogEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LogName)
    try {
        $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        [pscustomobject]@{
            LogName = $LogName
            State = $(if ($log.IsEnabled) { 'Enabled' } else { 'Disabled' })
            RecordCount = $log.RecordCount
            MaximumSizeInBytes = $log.MaximumSizeInBytes
            LogMode = [string]$log.LogMode
        }
    } catch {
        [pscustomobject]@{ LogName = $LogName; State = 'Unavailable'; RecordCount = $null; MaximumSizeInBytes = $null; LogMode = $null }
    }
}

function Get-GpoReadinessEventEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int[]]$Id,
        [string[]]$ProviderName = @(),
        [ValidateRange(1, 31)][int]$LookbackDays = 7,
        [ValidateRange(1, 5000)][int]$MaxEvents = 1000,
        [switch]$KerberosEncryption
    )
    $end = Get-Date
    $start = $end.AddDays(-$LookbackDays)
    $log = Get-GpoReadinessLogEvidence -LogName $LogName
    $counts = [ordered]@{}
    foreach ($eventId in $Id) { $counts[[string]$eventId] = 0 }
    $encryption = [ordered]@{ Rc4Fields = 0; DesFields = 0; AesFields = 0; OtherFields = 0; ParsedEvents = 0; MissingFields = 0; ParseErrors = 0 }
    $result = [ordered]@{
        LogName = $LogName; State = 'Unavailable'; Log = $log
        StartTimeUtc = $start.ToUniversalTime().ToString('o'); EndTimeUtc = $end.ToUniversalTime().ToString('o')
        MaxEvents = $MaxEvents; ReturnedEvents = 0; IncludedEvents = 0
        SampleMayBeTruncated = $false; Counts = $counts; Encryption = $null
        Limitation = 'A bounded sample cannot prove compatibility or complete audit coverage.'
    }
    if ($log.State -ne 'Enabled') { return [pscustomobject]$result }
    try {
        # Filter providers after retrieval. Provider registration varies across server versions.
        # The cap applies before that filter, so unrelated events cannot cause an unbounded read.
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Id; StartTime = $start; EndTime = $end } -MaxEvents $MaxEvents -ErrorAction Stop)
        $result.ReturnedEvents = $events.Count
        $result.SampleMayBeTruncated = ($events.Count -ge $MaxEvents)
        $result.State = $(if ($events.Count -eq 0) { 'NoMatchingEvents' } else { 'Observed' })
        foreach ($event in $events) {
            if ($ProviderName.Count -gt 0 -and $ProviderName -notcontains [string]$event.ProviderName) { continue }
            $idKey = [string]$event.Id
            if (-not $counts.Contains($idKey)) { continue }
            $counts[$idKey]++
            $result.IncludedEvents++
            if ($KerberosEncryption) {
                try {
                    $xml = New-Object System.Xml.XmlDocument
                    $xml.XmlResolver = $null
                    $settings = New-Object System.Xml.XmlReaderSettings
                    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
                    $settings.XmlResolver = $null
                    $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader([string]$event.ToXml())), $settings)
                    try { $xml.Load($reader) } finally { $reader.Dispose() }
                    $fields = @($xml.SelectNodes('//*[local-name()="EventData"]/*[local-name()="Data"]') | Where-Object {
                        $_.GetAttribute('Name') -in @('TicketEncryptionType', 'SessionKeyEncryptionType', 'PreAuthEncryptionType')
                    })
                    $encryption.ParsedEvents++
                    if ($fields.Count -eq 0) { $encryption.MissingFields++ }
                    foreach ($field in $fields) {
                        $raw = [string]$field.InnerText
                        if ($raw -match '^0x[0-9a-fA-F]{1,8}$') { $number = [Convert]::ToUInt32($raw.Substring(2), 16) }
                        elseif ($raw -match '^\d{1,9}$') { $number = [Convert]::ToUInt32($raw, 10) }
                        else { $encryption.ParseErrors++; continue }
                        if ($number -in @(23, 24)) { $encryption.Rc4Fields++ }
                        elseif ($number -in @(1, 3)) { $encryption.DesFields++ }
                        elseif ($number -in @(17, 18, 19, 20)) { $encryption.AesFields++ }
                        else { $encryption.OtherFields++ }
                    }
                } catch { $encryption.ParseErrors++ }
            }
        }
        if ($result.IncludedEvents -eq 0) { $result.State = 'NoMatchingEvents' }
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $result.State = 'NoMatchingEvents' }
        else { $result.State = 'ReadError' }
    }
    if ($KerberosEncryption) { $result.Encryption = $encryption }
    [pscustomobject]$result
}

function Get-GpoReadinessDeviceGuardEvidence {
    [CmdletBinding()]
    param()
    try {
        $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        [pscustomobject]@{
            State = 'Observed'
            VirtualizationBasedSecurityStatus = $guard.VirtualizationBasedSecurityStatus
            SecurityServicesConfigured = @($guard.SecurityServicesConfigured | ForEach-Object { [int]$_ })
            SecurityServicesRunning = @($guard.SecurityServicesRunning | ForEach-Object { [int]$_ })
            CredentialGuardRunning = (@($guard.SecurityServicesRunning) -contains 1)
        }
    } catch {
        [pscustomobject]@{ State = 'Unavailable'; CredentialGuardRunning = $null }
    }
}

function Get-GpoReadinessBaselineEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Context)
    $firewall = [ordered]@{ State = 'Unavailable'; Profiles = @() }
    try {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $firewall.Profiles = @($profiles | Where-Object { [string]$_.Name -in @('Domain', 'Private', 'Public') } | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; DefaultInboundAction = [string]$_.DefaultInboundAction; DefaultOutboundAction = [string]$_.DefaultOutboundAction }
        })
        if ($firewall.Profiles.Count -gt 0) { $firewall.State = 'Observed' }
    } catch { $firewall.State = 'Unavailable' }
    $defender = [ordered]@{ State = 'Unavailable' }
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if ($null -ne $status) {
            $defender.State = 'Observed'
            foreach ($property in @('AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'NISEnabled', 'IsTamperProtected', 'AntivirusSignatureAge')) {
                if ($status.PSObject.Properties.Name -contains $property) { $defender[$property] = $status.$property }
            }
        }
    } catch { $defender.State = 'Unavailable' }
    $lapsEligible = ([int]$Context.Version -ge 2019)
    [pscustomobject]@{
        WindowsLaps = [pscustomobject]@{
            PlatformEligible = $lapsEligible
            State = 'ReviewRequired'
            Purpose = $(if ($Context.Role -eq 'DomainController') { 'Recovery account password management' } else { 'Local administrator password management' })
            Policy = @(Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -Name 'BackupDirectory')
            Limitation = 'Platform eligibility does not verify updates, directory schema, permissions, password backup, or recovery.'
            Advice = $(if ($lapsEligible) { 'Review Windows LAPS prerequisites and recovery tests.' } else { 'Windows LAPS requires Server 2019 or later. Review supported legacy management or an operating system upgrade.' })
        }
        Firewall = [pscustomobject]$firewall
        Defender = [pscustomobject]$defender
        CredentialProtection = Get-GpoReadinessDeviceGuardEvidence
        Logging = @(
            Get-GpoReadinessLogEvidence -LogName 'Security'
            Get-GpoReadinessLogEvidence -LogName 'Microsoft-Windows-PowerShell/Operational'
            Get-GpoReadinessLogEvidence -LogName 'Microsoft-Windows-GroupPolicy/Operational'
        )
        LoggingPolicy = @(
            Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
            Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy'
        )
        Advice = @(
            'Compare effective settings with the Microsoft baseline for this server version and role.'
            'Check firewall rule scope and required application traffic before changes.'
            'Confirm antivirus ownership, exclusions, update health, and supported protection features.'
            'Confirm credential protection compatibility and actual runtime state.'
            'Review advanced audit policy, event retention, forwarding, and protection of collected logs.'
        )
    }
}

function Invoke-GpoReadinessCheck {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Control, [Parameter(Mandatory)][object]$Context)
    $kerberosPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $kdcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
    $ldapPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $kdcProviders = @('Microsoft-Windows-Kerberos-Key-Distribution-Center', 'Kdcsvc')
    $evidence = [ordered]@{
        Scope = 'Local computer only'
        ServerVersion = $Context.Version
        Role = $Context.Role
        Policy = @()
        Events = @()
        Limitations = @('Registry observations do not prove policy precedence or application compatibility.', 'Domain accounts, trusts, certificate mappings, and remote computers were not queried.')
    }
    switch ([string]$Control.Id) {
        'KerberosReadiness' {
            $evidence.Policy = @(
                Get-GpoReadinessRegistryEvidence -Path $kerberosPath -Name 'SupportedEncryptionTypes'
                Get-GpoReadinessRegistryEvidence -Path $kdcPath -Name 'DefaultDomainSupportedEncTypes'
                Get-GpoReadinessRegistryEvidence -Path $kerberosPath -Name 'RC4DefaultDisablementPhase'
            )
            if ($Context.Role -eq 'DomainController') {
                $evidence.Events = @(
                    Get-GpoReadinessEventEvidence -LogName 'Security' -Id @(4768, 4769) -ProviderName @('Microsoft-Windows-Security-Auditing') -KerberosEncryption
                    Get-GpoReadinessEventEvidence -LogName 'System' -Id (201..209) -ProviderName $kdcProviders
                )
            } else { $evidence.Limitations += 'Ticket issuance evidence requires a separate check on each relevant domain controller.' }
            $evidence.Guidance = @(
                'April 14, 2026 updates changed assumed encryption defaults for accounts without explicit settings.'
                'July 2026 updates removed the temporary RC4DefaultDisablementPhase switch.'
                'Inspect available AES keys, account settings, trusts, and non-Windows applications before further restrictions.'
                'Keep current enforcement active during inspection. Missing events do not prove readiness.'
            )
            $reason = 'Kerberos compatibility requires account, trust, application, and audit coverage review.'
        }
        'CertificateReadiness' {
            $evidence.Policy = @(
                Get-GpoReadinessRegistryEvidence -Path $kdcPath -Name 'StrongCertificateBindingEnforcement'
                Get-GpoReadinessRegistryEvidence -Path $kdcPath -Name 'UseSubjectAltName'
            )
            if ($Context.Role -eq 'DomainController') {
                $evidence.Events = @(Get-GpoReadinessEventEvidence -LogName 'System' -Id @(39, 40, 41) -ProviderName $kdcProviders)
            } else { $evidence.Limitations += 'Certificate authentication evidence requires checks on the issuing service and relevant domain controllers.' }
            $evidence.Guidance = @(
                'Updates released September 9, 2025 removed support for StrongCertificateBindingEnforcement.'
                'Check installed updates, strong certificate mappings, enrollment, renewal, and application authentication.'
                'The obsolete compatibility value is evidence only. It cannot provide rollback on updated systems.'
            )
            $reason = 'Certificate mapping and application checks remain required, regardless of event counts.'
        }
        'LdapReadiness' {
            $evidence.Policy = @(Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity')
            if ($Context.Role -eq 'DomainController') {
                $evidence.Policy += @(
                    Get-GpoReadinessRegistryEvidence -Path $ldapPath -Name 'LDAPServerIntegrity'
                    Get-GpoReadinessRegistryEvidence -Path $ldapPath -Name 'LDAPServerEnforceIntegrity'
                    Get-GpoReadinessRegistryEvidence -Path $ldapPath -Name 'LdapEnforceChannelBinding'
                    Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events'
                )
                $evidence.Events = @(Get-GpoReadinessEventEvidence -LogName 'Directory Service' -Id @(2886, 2887, 2888, 2889, 3039, 3040, 3041, 3074, 3075) -ProviderName @('Microsoft-Windows-ActiveDirectory_DomainService', 'NTDS LDAP'))
            } else { $evidence.Limitations += 'Server signing and channel binding evidence requires a domain controller check.' }
            $evidence.Guidance = @(
                'Server signing value 1 permits unsigned requests. Value 2 requires signing.'
                'Server 2025 has a separate signing enforcement policy that takes precedence.'
                'Test client signing, encrypted binds, channel binding, and third-party applications separately.'
                'Absent events can reflect disabled diagnostics, insufficient retention, or inactive applications.'
            )
            $reason = 'LDAP readiness requires effective policy, logging coverage, and application tests.'
        }
        'NtlmReadiness' {
            $evidence.Policy = @(
                Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
                Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'BlockNtlmv1SSO'
                Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic'
                Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'
            )
            $evidence.Events = @(Get-GpoReadinessEventEvidence -LogName 'Microsoft-Windows-NTLM/Operational' -Id @(4024, 4025, 8001, 8002, 8003, 8004) -ProviderName @('Microsoft-Windows-NTLM'))
            $evidence.CredentialProtection = Get-GpoReadinessDeviceGuardEvidence
            $evidence.Guidance = @(
                'Server 2025 removed the NTLMv1 protocol. Older server versions still need applicable controls.'
                'October 13, 2026 updates changed the absent BlockNtlmv1SSO default on eligible systems without Credential Guard.'
                'Check update status and test automatic Wi-Fi, Ethernet, VPN, and application authentication.'
                'An absent registry value does not identify the effective default without build and update evidence.'
            )
            $reason = 'NTLM dependencies and credential protection require review before further restrictions.'
        }
        'MdnsReadiness' {
            $evidence.Policy = @(
                Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS'
                Get-GpoReadinessRegistryEvidence -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
            )
            $listeners = [ordered]@{ State = 'Unavailable'; Udp5353Endpoints = $null; ProcessCount = $null }
            try {
                $endpoints = @(Get-NetUDPEndpoint -LocalPort 5353 -ErrorAction Stop)
                $listeners.State = 'Observed'
                $listeners.Udp5353Endpoints = $endpoints.Count
                $listeners.ProcessCount = @($endpoints | Select-Object -ExpandProperty OwningProcess -Unique).Count
            } catch {
                if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*') {
                    $listeners.State = 'NoMatchingEndpoints'; $listeners.Udp5353Endpoints = 0; $listeners.ProcessCount = 0
                }
            }
            $evidence.Listeners = [pscustomobject]$listeners
            $evidence.Guidance = @(
                'Multicast DNS uses UDP port 5353. Applications can provide their own implementation.'
                'The EnableMulticast policy controls LLMNR, a different name resolution protocol.'
                'Registry values and a listener snapshot do not prove that multicast DNS traffic is blocked.'
                'Review required discovery traffic and effective firewall rules in an isolated test.'
            )
            $reason = 'Multicast DNS requires application and traffic review. Registry evidence alone is insufficient.'
        }
        'BaselineCoverage' {
            $evidence.Coverage = Get-GpoReadinessBaselineEvidence -Context $Context
            $reason = 'Baseline evidence is advisory. It does not establish full server compliance.'
        }
        default { return New-GpoResult -Control $Control -Status 'Error' -Reason 'No readiness check exists for this control.' -Evidence $evidence }
    }
    New-GpoResult -Control $Control -Status 'ReviewRequired' -Reason $reason -Evidence ([pscustomobject]$evidence)
}
