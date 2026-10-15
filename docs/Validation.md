# Validation before deployment

GPOScripts is a collection of server hardening tools. Local tests verify code behavior. They do not establish domain compatibility or deployment readiness.

**End-to-end tests: NOT RUN.** The matrix below records required domain tests. Mocked tests do not change this status.

The repository supports Windows Server 2016, 2019, 2022, and 2025 while each version remains supported. Tests must distinguish member servers from domain controllers.

The commands below use a disposable test domain named `lab.example.test`. The repository location is `C:\Lab\GPOScripts`. These names are examples.

## Required test matrix

The test owner records the operating system, full build, installed updates, role, PowerShell version, and application versions for every result.

| Server version | Member server | Domain controller | Required distinctions |
|---|---|---|---|
| 2016 | NOT RUN | NOT RUN | Older optional features and unavailable Windows LAPS |
| 2019 | NOT RUN | NOT RUN | Windows LAPS update prerequisites and older Kerberos event fields |
| 2022 | NOT RUN | NOT RUN | Existing policies, missing values, and inherited settings |
| 2025 | NOT RUN | NOT RUN | Signing defaults, separate LDAP enforcement, and removed features |

Windows LAPS manages administrator passwords. Windows LAPS supports Server 2019 and later with applicable updates. Domain controllers use separate recovery-account requirements. [Microsoft LAPS guidance](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)

Each matrix entry needs Windows PowerShell 5.1 verification. PowerShell 7 tests provide additional code coverage. PowerShell 7 tests do not replace native Group Policy checks.

## Safe test preparation

CAUTION: Hardening can interrupt authentication and remote access. These steps require an isolated domain and verified recovery access.

1. Create isolated member servers and domain controllers for each required version.
2. Record the test domain and each target computer in the test record.
3. Verify console access and the approved recovery procedure for each target.
4. Install the reviewed repository at `C:\Lab\GPOScripts` on the test administrator computer.
5. Import the module with `Import-Module 'C:\Lab\GPOScripts\PowerShell\GPOScripts\GPOScripts.psd1' -Force`.
6. Record definitions with `Get-GpoControl | ConvertTo-Json -Depth 20 | Set-Content 'C:\Lab\controls.json'`.
7. Record initial assessment with `Get-GpoAssessment | ConvertTo-Json -Depth 30 | Set-Content 'C:\Lab\assessment-before.json'`.

The test owner must preserve existing registry values, value types, optional features, policy links, and application results. Screenshots alone cannot prove correct rollback.

## Read-only assessment checks

Readiness checks inspect the local computer only. They do not enumerate domain accounts, trusts, certificate mappings, or remote computers.

Event queries cover seven days and return at most 1,000 records per query. The limit applies before provider filtering. A full sample may be incomplete.

The output includes event counts and encryption categories. It excludes account names, addresses, process identifiers, and full event text. Registry checks export expected numeric policy values only.

Every readiness control returns `ReviewRequired`. Missing events, disabled logs, denied access, and unavailable commands cannot establish readiness. Event collection does not enable auditing.

1. Run `Get-GpoAssessment -Id KerberosReadiness,CertificateReadiness,LdapReadiness,NtlmReadiness,MdnsReadiness,BaselineCoverage` on each test target.
2. Record each unavailable evidence source and its cause.
3. Verify that denied access produces `ReviewRequired` or `Error`.
4. Verify that empty event logs do not produce `Compliant`.
5. Verify that the output excludes account names and full event text.
6. Check audit policy, log retention, and collection gaps separately.

## Local application checks

The following example selects `Smb1ServerDisabled`, the control that disables the older SMB server protocol. The catalogue supplies the exact available identifiers.

1. Preview the change with `Invoke-GpoLocalApply -Id Smb1ServerDisabled -BackupDirectory 'C:\Lab\Backups' -AcceptCompatibilityRisk -WhatIf`.
2. Verify that preview creates no backup files and changes no settings.
3. Apply the control with `$localChange = Invoke-GpoLocalApply -Id Smb1ServerDisabled -BackupDirectory 'C:\Lab\Backups' -AcceptCompatibilityRisk -Confirm`.
4. Record `$localChange.SnapshotPath` in the test record.
5. Verify that the backup contains the original value, type, and existence state.
6. Verify that unrelated registry values remain unchanged.
7. Run `Get-GpoAssessment -Id Smb1ServerDisabled`.
8. Repeat `Invoke-GpoLocalApply -Id Smb1ServerDisabled -BackupDirectory 'C:\Lab\Backups' -AcceptCompatibilityRisk -Confirm`.
9. Verify that repeated application preserves previous backups and produces the same intended settings.

For each control, the test owner repeats these checks with present values, absent values, conflicting values, and unexpected types. Feature controls also need absent-feature cases.

CAUTION: Restarting a server interrupts services. A domain controller restart also reduces authentication capacity.

1. Restart the isolated target through its approved console procedure when the selected control requires a restart.
2. Record the restart time and successful service recovery.
3. Repeat the assessment and application tests after the restart.

## Group Policy checks

A Group Policy Object (GPO) contains domain policy settings. Creation must leave the GPO unlinked. Policy storage, replication, and client processing require separate checks.

`SmbSigningRequired` is the control that requires SMB signing. The update below adds this setting to the newly created GPO.

1. Preview creation with `New-GpoConfiguration -Name 'Lab - SMB hardening' -Id Smb1ServerDisabled -Domain 'lab.example.test' -Server 'dc01.lab.example.test' -TargetVersion 2022 -Role MemberServer -BackupDirectory 'C:\Lab\GpoBackups' -AcceptCompatibilityRisk -WhatIf`.
2. Verify that preview creates no GPO, files, or links.
3. Create the GPO with `New-GpoConfiguration -Name 'Lab - SMB hardening' -Id Smb1ServerDisabled -Domain 'lab.example.test' -Server 'dc01.lab.example.test' -TargetVersion 2022 -Role MemberServer -BackupDirectory 'C:\Lab\GpoBackups' -AcceptCompatibilityRisk -Confirm`.
4. Record the returned GPO identifier and manifest path.
5. Export the GPO with `Get-GPOReport -Name 'Lab - SMB hardening' -Domain 'lab.example.test' -Server 'dc01.lab.example.test' -ReportType Xml -Path 'C:\Lab\gpo.xml'`.
6. Verify the intended settings, types, scope, and absence of duplicate preference items.
7. Verify that creation added no links.
8. Verify that an existing GPO requires `-UpdateExisting` before changes.
9. Verify that an update saves a restorable backup before its first change.
10. Test an update with `$gpoUpdate = New-GpoConfiguration -Name 'Lab - SMB hardening' -Id Smb1ServerDisabled,SmbSigningRequired -Domain 'lab.example.test' -Server 'dc01.lab.example.test' -TargetVersion 2022 -Role MemberServer -BackupDirectory 'C:\Lab\GpoBackups' -UpdateExisting -AcceptCompatibilityRisk -Confirm`.
11. Record `$gpoUpdate.ManifestPath` in the test record.
12. Verify that the update created `completion.json` beside its recovery manifest.
13. Repeat the update with `$gpoRepeat = New-GpoConfiguration -Name 'Lab - SMB hardening' -Id Smb1ServerDisabled,SmbSigningRequired -Domain 'lab.example.test' -Server 'dc01.lab.example.test' -TargetVersion 2022 -Role MemberServer -BackupDirectory 'C:\Lab\GpoBackups' -UpdateExisting -AcceptCompatibilityRisk -Confirm`.
14. Verify that `$gpoRepeat.Status` is `Unchanged` and `$gpoRepeat.ManifestPath` is empty.
15. Verify that the repeated update created no new backup or recovery files.

The recovery test uses `$gpoUpdate.ManifestPath`. An identical update returns `Unchanged` without creating a manifest. Its result must not replace the earlier recovery reference.

SYSVOL is the shared folder that stores domain policy files. A successful GPO command does not prove SYSVOL replication or client application.

1. Compare the GPO version and contents across the isolated domain controllers.
2. Check SYSVOL access and replication health independently.
3. Verify that the client can read the intended policy files.
4. Record any replication delay or version mismatch as an unresolved failure.

## Recovery checks

Rollback restores recorded state. It must not blindly enable older protocols or weaker algorithms.

The GPO recovery test must finish before the policy processing test. Automatic recovery requires an unlinked GPO and the original completion record.

If initial application changed no settings, no snapshot exists. The test owner needs a controlled initial difference before testing recovery.

1. Preview local recovery with `Restore-GpoLocalState -Path $localChange.SnapshotPath -WhatIf`.
2. Verify that the preview changes no files or settings.
3. Restore that backup with `Restore-GpoLocalState -Path $localChange.SnapshotPath -Confirm`.
4. Compare restored values, types, and absence states with the initial record.
5. Verify that unrelated values remain unchanged.
6. Verify that a backup for another computer fails safely.
7. Verify that a damaged or altered backup fails safely.
8. Repeat the application tests after recovery.

A local backup cannot reverse domain policy precedence. A later policy refresh can restore a domain setting.

The completion record must match the recovery manifest. Current policy contents, permissions, and report-visible filters must match the recorded completed state.

1. Verify that the test GPO remains unlinked.
2. Verify that `completion.json`, its recovery manifest, and its backup remain unchanged.
3. Preview GPO recovery with `Restore-GpoConfiguration -ManifestPath $gpoUpdate.ManifestPath -WhatIf`.
4. Verify that the preview changes no files or settings.
5. Restore the GPO with `$gpoRecovery = Restore-GpoConfiguration -ManifestPath $gpoUpdate.ManifestPath -Confirm`.
6. Record `$gpoRecovery.PreservedManifestPath` for the backup saved before restoration.
7. Verify policy contents and versions after replication.
8. Verify that recovery never deletes a newly created GPO automatically.

The recovery tests also need separate disposable GPOs for later edits and damaged records. These cases must fail before restoration.

1. Verify refusal after another administrator changes policy settings or permissions.
2. Verify refusal when the completion record is missing or does not match the manifest.
3. Verify refusal when the GPO has a link.
4. Verify refusal when backup files have changed.

Restoring a GPO changes its stored configuration. It does not restore each endpoint's previous values. Values outside managed `Policies` paths can remain after policy removal.

1. Record endpoint values before linking the test GPO.
2. Verify endpoint recovery separately for settings outside managed `Policies` paths.
3. Use a reviewed endpoint recovery procedure when a restored GPO leaves a changed value behind.

If GPO application fails before it creates a completion record, automatic recovery refuses the manifest. The preserved backup requires manual review and recovery.

CAUTION: Manual recovery can replace later policy changes. Recovery requires verified identity, scope, backup contents, and current state.

1. Preserve the failed operation's manifest, backup files, and error record.
2. Compare the current unlinked GPO with the preserved backup.
3. Obtain approval for the exact manual recovery procedure after reviewing any later changes.
4. Recover the existing GPO through that approved procedure.
5. Verify stored policy and endpoint behavior separately.

A failed creation can leave a new unlinked GPO. Its intent record supports manual review. The tool never deletes that GPO automatically.

## Policy processing checks

The preceding GPO recovery test must pass before linking. Recovery returns the example GPO to its original configuration without the added signing settings.

CAUTION: Linking a GPO changes computers within its scope. A wrong link can interrupt the entire domain.

1. Link the GPO only to the dedicated test organizational unit through the approved test procedure.
2. Refresh the target policy with `gpupdate.exe /target:computer /force`.
3. Export applied policy with `gpresult.exe /scope computer /h C:\Lab\applied-policy.html`.
4. Check the Group Policy operational log for processing failures.
5. Compare applied policy, local registry evidence, and observed application behavior.
6. Repeat policy processing and verify that settings remain stable.

The production approval must identify the intended organizational unit, security filters, exclusions, and policy precedence. This tool never creates those links automatically.

## Authentication and application tests

Kerberos is the primary domain authentication protocol. RC4 is an older Kerberos cipher. Updated defaults do not remove every explicit RC4 dependency.

April 14, 2026 updates changed the assumed defaults for accounts without explicit encryption settings. July 2026 updates removed the temporary rollback switch. The test owner must assess installed updates. [Microsoft Kerberos timeline](https://support.microsoft.com/en-us/servicing/os/windows/2025/11/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2)

1. Review events 4768 and 4769 on each relevant domain controller.
2. Review Kerberos service events 201 through 209 where the installed updates provide them.
3. Verify available AES keys and encryption settings for affected accounts through the approved directory review.
4. Test trusts, scheduled tasks, services, file access, and non-Windows integrations.
5. Keep existing enforcement active during evidence collection.

Certificate authentication requires strong mappings on updated systems. Updates released September 9, 2025 removed support for the old compatibility switch. [Microsoft certificate guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)

1. Review certificate events 39, 40, and 41 on each relevant domain controller.
2. Verify certificate mappings, enrollment, renewal, and certificate-based application authentication.
3. Verify that the assessment treats the obsolete compatibility switch as evidence only.

LDAP is the directory access protocol. Signing and channel binding protect different parts of authentication. Server 2025 has a separate signing enforcement policy. [Microsoft LDAP guidance](https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy)

1. Verify signing behavior with signed and unsigned test connections.
2. Verify encrypted LDAP connections and channel binding separately.
3. Test applications, appliances, certificate enrollment, directory searches, and policy processing.
4. Verify that diagnostics cover active application use before accepting an empty sample.

NTLM is an older authentication protocol family. Server 2025 removed NTLMv1. Separate controls affect credentials derived from NTLMv1.

October 13, 2026 updates changed the absent `BlockNtlmv1SSO` default on eligible systems without Credential Guard. Automatic network authentication can fail. [Microsoft NTLM guidance](https://support.microsoft.com/en-us/servicing/os/windows/docs/2025/08/upcoming-changes-to-ntlmv1-in-windows-11-version-24h2-and-windows-server-2025)

1. Verify the installed updates and Credential Guard runtime state.
2. Review events 4024 and 4025 where available.
3. Test automatic Wi-Fi, Ethernet, VPN, and application authentication where these services apply.

Multicast DNS is a discovery protocol. Applications can implement it independently of Windows settings. A registry value cannot prove that traffic is blocked.

1. Test required discovery with packet evidence in the isolated network.
2. Compare UDP port 5353 traffic with effective firewall rules and application requirements.

Transport controls require tests for inbound and outbound connections. Applications can use libraries that do not follow Windows Schannel settings.

1. Test web services, remote management, directory encryption, databases, monitoring, backup, and update connections.
2. Test supported TLS versions and rejected older versions with independent client tools.
3. Test file sharing and signing in both connection directions.
4. Record the client version, server version, negotiated protocol, and result for each test.

## Baseline coverage and release limits

`BaselineCoverage` is the advisory control for baseline coverage. It reports Windows LAPS, firewall, Defender, credential protection, and logging evidence. It never applies settings or establishes full compliance.

Separate optional controls configure selected settings. Each control needs its own compatibility tests and explicit selection.

| Optional control | Purpose | Required evidence |
|---|---|---|
| `LapsBackupToActiveDirectory` | Back up administrator passwords | Member server eligibility, updates, schema, permissions, backup, and recovery |
| `FirewallEnabled` | Enable firewall profiles | Effective profiles, service health, application rules, and console access |
| `PowerShellScriptBlockLoggingEnabled` | Log Windows PowerShell scripts | New process events, protected collection, access restrictions, and retention |
| `LsaProtectionEnabled` | Protect the authentication process | Server 2025 eligibility, extension compatibility, restart, and runtime verification |

Windows LAPS can rotate passwords after application. Registry recovery cannot restore those passwords. The password control does not configure recovery passwords on domain controllers.

Script logs can contain credentials and other sensitive data. Windows PowerShell 5.1 logging does not configure PowerShell 7 logging.

The authentication protection control does not create a firmware lock. Existing firmware locks require separate recovery review. Registry values alone cannot prove runtime protection.

The test owner must review the Microsoft baseline for each server version and role. Directory prerequisites, firewall rules, antivirus exclusions, and audit forwarding require separate evidence.

1. Record each matrix result as `Passed`, `Failed`, `NOT RUN`, or `Not applicable`.
2. Attach evidence and an explanation to every result.
3. Keep deployment blocked while required tests fail or remain untested.
4. Obtain approval for the exact settings, scope, restart plan, and verified recovery procedure before production deployment.

Your action: none
