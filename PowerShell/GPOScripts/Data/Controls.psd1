# Reviewed against Microsoft guidance on 2026-10-15.
# Supported Windows Server versions: 2016, 2019, 2022, and 2025.
# Definitions describe explicit settings. Registry evidence alone does not prove effective policy or compatibility.
@{
    SchemaVersion = 1
    Controls = @(@{
        Id = 'Ssl3Disabled'
        Title = 'Disable Secure Sockets Layer 3.0'
        Category = 'TransportSecurity'
        Description = 'Disable SSL 3.0 for Schannel clients and servers. Applications that use other security libraries require separate checks.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings', 'https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls', 'https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/ad-dmn-services/enable-support-tls-environment')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            Name = 'Enabled'
            Type = 'DWord'
            Value = 0
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
            Name = 'DisabledByDefault'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            Name = 'Enabled'
            Type = 'DWord'
            Value = 0
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            Name = 'DisabledByDefault'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'Tls10Disabled'
        Title = 'Disable Transport Layer Security 1.0'
        Category = 'TransportSecurity'
        Description = 'Disable TLS 1.0 for Schannel clients and servers. Applications that use other security libraries require separate checks.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings', 'https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls', 'https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/ad-dmn-services/enable-support-tls-environment')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            Name = 'Enabled'
            Type = 'DWord'
            Value = 0
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
            Name = 'DisabledByDefault'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            Name = 'Enabled'
            Type = 'DWord'
            Value = 0
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            Name = 'DisabledByDefault'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'Tls11Disabled'
        Title = 'Disable Transport Layer Security 1.1'
        Category = 'TransportSecurity'
        Description = 'Disable TLS 1.1 for Schannel clients and servers. Applications that use other security libraries require separate checks.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings', 'https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls', 'https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/ad-dmn-services/enable-support-tls-environment')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            Name = 'Enabled'
            Type = 'DWord'
            Value = 0
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
            Name = 'DisabledByDefault'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            Name = 'Enabled'
            Type = 'DWord'
            Value = 0
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            Name = 'DisabledByDefault'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'Tls12Enabled'
        Title = 'Enable Transport Layer Security 1.2'
        Category = 'TransportSecurity'
        Description = 'Enable TLS 1.2 for Schannel clients and servers. Applications that use other security libraries require separate checks.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings', 'https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls', 'https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/ad-dmn-services/enable-support-tls-environment')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            Name = 'Enabled'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            Name = 'DisabledByDefault'
            Type = 'DWord'
            Value = 0
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            Name = 'Enabled'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            Name = 'DisabledByDefault'
            Type = 'DWord'
            Value = 0
        })
    }, @{
        Id = 'DotNetSystemTls'
        Title = 'Use system protocols in .NET Framework'
        Category = 'TransportSecurity'
        Description = 'Use system protocol defaults and strong cryptography for .NET Framework clients. Application settings can override these defaults.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls')
        Registry = @(@{
            Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
            Name = 'SystemDefaultTlsVersions'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
            Name = 'SchUseStrongCrypto'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
            Name = 'SystemDefaultTlsVersions'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
            Name = 'SchUseStrongCrypto'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'
            Name = 'SystemDefaultTlsVersions'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'
            Name = 'SchUseStrongCrypto'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
            Name = 'SystemDefaultTlsVersions'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
            Name = 'SchUseStrongCrypto'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'Smb1ServerDisabled'
        Title = 'Disable Server Message Block version 1'
        Category = 'FileSharing'
        Description = 'Disable the SMB1 server. This setting does not remove the optional feature or disable the SMB1 client.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Name = 'SMB1'
            Type = 'DWord'
            Value = 0
        })
    }, @{
        Id = 'SmbSigningRequired'
        Title = 'Require Server Message Block signing'
        Category = 'FileSharing'
        Description = 'Require signing for SMB clients and servers. Test all file shares and devices before enforcement.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
            Name = 'RequireSecuritySignature'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Name = 'RequireSecuritySignature'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'SmbClientEncryptionRequired'
        Title = 'Require Server Message Block encryption'
        Category = 'FileSharing'
        Description = 'Require encryption for outbound SMB connections on Server 2025. Destinations must support SMB3 encryption.'
        Kind = 'Registry'
        MinBuild = 26100
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/windows-server/storage/file-server/configure-smb-client-require-encryption')
        Registry = @(@{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            Name = 'RequireEncryption'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'AnonymousSamEnumerationBlocked'
        Title = 'Block anonymous account enumeration'
        Category = 'AccountSecurity'
        Description = 'Block anonymous enumeration of local Security Accounts Manager accounts. This control does not protect domain controller account enumeration.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            Name = 'RestrictAnonymousSAM'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'LlmnrDisabled'
        Title = 'Disable local multicast name resolution'
        Category = 'NameResolution'
        Description = 'Disable Link-Local Multicast Name Resolution. Validate DNS resolution before enforcement.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient#turn_off_multicast')
        Registry = @(@{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            Name = 'EnableMulticast'
            Type = 'DWord'
            Value = 0
        })
    }, @{
        Id = 'NtlmV2Only'
        Title = 'Require NTLM version 2'
        Category = 'Authentication'
        Description = 'Set LAN Manager authentication level 5. Refuse LM and NTLM version 1. This does not disable NTLM version 2.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc', 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            Name = 'LmCompatibilityLevel'
            Type = 'DWord'
            Value = 5
        })
    }, @{
        Id = 'KerberosAesAllowed'
        Title = 'Allow Kerberos AES and future types'
        Category = 'Authentication'
        Description = 'Allow AES and future Kerberos encryption types. Exclude DES and RC4. Account keys and service compatibility require separate checks.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc', 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos')
        Registry = @(@{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            Name = 'SupportedEncryptionTypes'
            Type = 'DWord'
            Value = 2147483640
        })
    }, @{
        Id = 'LdapClientSigningRequired'
        Title = 'Require directory client signing'
        Category = 'DirectorySecurity'
        Description = 'Require LDAP client signing where TLS does not protect the connection. Validate client applications and directory servers.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements', 'https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
            Name = 'LDAPClientIntegrity'
            Type = 'DWord'
            Value = 2
        })
    }, @{
        Id = 'LdapServerSigningRequired'
        Title = 'Require directory server signing'
        Category = 'DirectorySecurity'
        Description = 'Require LDAP signing on domain controllers running Server 2016 through Server 2022. Reject unsigned requests without TLS.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            Name = 'LDAPServerIntegrity'
            Type = 'DWord'
            Value = 2
        })
        MaxBuild = 26099
    }, @{
        Id = 'LdapServerSigningEnforced'
        Title = 'Enforce directory server signing'
        Category = 'DirectorySecurity'
        Description = 'Enforce LDAP signing on Server 2025 domain controllers. This setting takes precedence over the older signing policy.'
        Kind = 'Registry'
        MinBuild = 26100
        Roles = @('DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing', 'https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            Name = 'LDAPServerEnforceIntegrity'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'LdapChannelBindingRequired'
        Title = 'Require directory channel binding'
        Category = 'DirectorySecurity'
        Description = 'Require channel binding for applicable LDAP sessions using TLS and SASL. Current security updates and compatible clients are prerequisites.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding', 'https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            Name = 'LdapEnforceChannelBinding'
            Type = 'DWord'
            Value = 2
        })
    }, @{
        Id = 'PowerShell2Disabled'
        Title = 'Disable PowerShell version 2'
        Category = 'OptionalFeatures'
        Description = 'Disable the PowerShell 2 optional features when present. Feature absence is acceptable only after a successful feature inventory.'
        Kind = 'Feature'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/windows/whats-new/removed-features')
        Features = @('MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root')
    }, @{
        Id = 'LapsBackupToActiveDirectory'
        Title = 'Back up administrator passwords'
        Category = 'AccountSecurity'
        Description = 'Select Active Directory backup for Windows LAPS on member servers. Server 2019 and Server 2022 require the April 11, 2023 update or later. Validate schema, permissions, encryption, password recovery, and existing policy ownership before application. Password rotation can start after application. Registry recovery cannot restore passwords that LAPS changes. This control does not configure domain controller recovery passwords.'
        Kind = 'Registry'
        MinBuild = 17763
        Roles = @('MemberServer')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings', 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview', 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory')
        Registry = @(@{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            Name = 'BackupDirectory'
            Type = 'DWord'
            Value = 2
        })
    }, @{
        Id = 'LsaProtectionEnabled'
        Title = 'Protect the authentication process'
        Category = 'AccountSecurity'
        Description = 'Enable Local Security Authority protection without creating a firmware lock on Server 2025. Validate authentication extensions and review Code Integrity events before application. Existing firmware locks require separate recovery review. Restart the server and verify protection through WinInit event 12. Registry evidence alone does not prove that protection runs.'
        Kind = 'Registry'
        MinBuild = 26100
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $true
        Sources = @('https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc', 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection')
        Registry = @(@{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            Name = 'RunAsPPL'
            Type = 'DWord'
            Value = 2
        })
    }, @{
        Id = 'PowerShellScriptBlockLoggingEnabled'
        Title = 'Log Windows PowerShell scripts'
        Category = 'Logging'
        Description = 'Enable script block logging for Windows PowerShell 5.1. Logs can contain credentials and other sensitive data. Validate protected event logging, access restrictions, retention, storage, and collection before application. Verify events from a new Windows PowerShell process. PowerShell 7 requires separate policy configuration.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowspowershell', 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1', 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings?view=powershell-7.5')
        Registry = @(@{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Name = 'EnableScriptBlockLogging'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'FirewallEnabled'
        Title = 'Enable Windows Firewall'
        Category = 'NetworkSecurity'
        Description = 'Enable Windows Firewall for domain, private, and public profiles. Validate required allow rules, policy ownership, and console access before application. Verify the firewall service and effective profiles after application. This control does not create application rules or provide a complete firewall baseline.'
        Kind = 'Registry'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $true
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2100c552-7f37-4a7f-9fa0-2a864ab87212', 'https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc')
        Registry = @(@{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            Name = 'EnableFirewall'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            Name = 'EnableFirewall'
            Type = 'DWord'
            Value = 1
        }, @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            Name = 'EnableFirewall'
            Type = 'DWord'
            Value = 1
        })
    }, @{
        Id = 'KerberosReadiness'
        Title = 'Check Kerberos readiness'
        Category = 'Authentication'
        Description = 'Inspect available account and event evidence. Missing evidence cannot establish application compatibility.'
        Kind = 'Audit'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $false
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos', 'https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc')
    }, @{
        Id = 'CertificateReadiness'
        Title = 'Check certificate authentication'
        Category = 'Authentication'
        Description = 'Check certificate authentication evidence. Obsolete enforcement switches do not establish compliance.'
        Kind = 'Audit'
        MinBuild = 14393
        Roles = @('DomainController')
        CompatibilityRisk = $false
        RestartRequired = $false
        Sources = @('https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers')
    }, @{
        Id = 'LdapReadiness'
        Title = 'Check directory readiness'
        Category = 'DirectorySecurity'
        Description = 'Check LDAP signing, channel binding, and available events. No observed failures do not establish compatibility.'
        Kind = 'Audit'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $false
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing', 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding', 'https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc')
    }, @{
        Id = 'NtlmReadiness'
        Title = 'Check NTLM readiness'
        Category = 'Authentication'
        Description = 'Inspect available NTLM evidence. A policy value or empty event query cannot establish protocol migration.'
        Kind = 'Audit'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $false
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1')
    }, @{
        Id = 'MdnsReadiness'
        Title = 'Check multicast DNS exposure'
        Category = 'NameResolution'
        Description = 'Inspect multicast DNS listeners and firewall evidence. DNS Client registry values do not cover other applications.'
        Kind = 'Audit'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $false
        RestartRequired = $false
        Sources = @('https://techcommunity.microsoft.com/blog/networkingblog/mdns-in-the-enterprise/3275777/')
    }, @{
        Id = 'BaselineCoverage'
        Title = 'Check baseline coverage'
        Category = 'PlatformSecurity'
        Description = 'Report areas outside this catalogue. Compare the target with the current Microsoft security baseline.'
        Kind = 'Audit'
        MinBuild = 14393
        Roles = @('MemberServer', 'DomainController')
        CompatibilityRisk = $false
        RestartRequired = $false
        Sources = @('https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc')
    })
}
