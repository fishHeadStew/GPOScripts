# GPOScripts

GPOScripts assesses security settings on supported Windows servers. Changes require an explicit command and a recovery location.

Version 2 replaces direct registry scripts with shared controls, recorded recovery, and verification.

## Support

The target versions are Windows Server 2016, 2019, 2022, and 2025. Domain controllers and member servers have separate controls.

The local commands require a 64-bit PowerShell process. Windows PowerShell 5.1 is the primary runtime. The isolated tests also run in PowerShell 7.

Group Policy creation requires the Microsoft GroupPolicy module. The documented administration runtime is Windows PowerShell 5.1 with the Group Policy management tools.

Server 2016 reaches its recorded support end on January 12, 2027. Local assessment, local application, and Group Policy preparation reject expired versions.

[Microsoft support dates](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)

## Assessment

Assessment does not change settings. Some evidence requires an elevated session. A failed read produces an explicit error or unavailable evidence.

1. Run `Import-Module .\PowerShell\GPOScripts\GPOScripts.psd1` from the repository directory.
2. Run `Get-GpoControl | Select-Object Id, Title, Kind, Roles` to list the controls.
3. Run `Get-GpoAssessment | Format-Table Id, Status, Reason -Wrap` to assess the local server.

The command entry point also defaults to assessment.

1. Run `.\Invoke-GPOScripts.ps1 -OutputPath .\assessment.json` to save a new report.

The report directory must exist. The command refuses to replace an existing report.

## Results

| Status | Meaning |
| --- | --- |
| Compliant | Recorded values match the selected definition. Application validation remains required. |
| NonCompliant | Recorded values differ. Defaults and policy ownership need review before changes. |
| NotApplicable | The server version or role does not support the control. |
| ReviewRequired | The evidence requires further checks. Missing events do not prove compatibility. |
| Error | A check failed. The tool cannot determine the setting. |
| Planned | A local preview describes changes without writing settings or recovery files. |
| Unchanged | Selected settings already match. No configuration write was required. |
| Configured | Local writes passed readback checks. Application validation remains required. |
| ConfiguredUnlinked | The tool wrote settings to an unlinked Group Policy object. |
| Restored | Local values returned to the recorded state. Application validation remains required. |
| RestoredUnlinked | The tool restored an unlinked Group Policy object from its recorded backup. |

Registry evidence does not prove active policy precedence or runtime behavior. Pending feature changes require a restart before final validation.

## Selected controls

The catalogue contains 27 controls. Each control records its sources, supported builds, roles, compatibility risk, and restart requirement.

| Control group | Coverage |
| --- | --- |
| Network encryption | Both connection directions for obsolete protocols, TLS 1.2, and .NET protocol selection |
| File sharing | SMB1 server disablement, required signing, and Server 2025 outbound encryption |
| Authentication | Modern authentication levels, allowed Kerberos encryption, and directory signing |
| Directory protection | Separate Server 2025 signing enforcement and channel binding |
| Local exposure | Anonymous account enumeration and multicast name resolution |
| Optional features | PowerShell 2.0 feature assessment and disablement |
| Optional protection | Administrator password backup, authentication protection, script logging, and Windows Firewall |
| Readiness | Kerberos, certificates, directory access, older authentication, and multicast DNS |
| Baseline evidence | Password management eligibility, firewall, antivirus, credential protection, and logging |

SMB means Server Message Block, the Windows file sharing protocol. TLS means Transport Layer Security, which protects network connections.

The SMB1 setting changes the server configuration. It does not remove the optional SMB1 component or configure every client dependency.

The toolkit retains modern SMB2 and SMB3 support. It does not write a custom cipher list or an obsolete certificate compatibility switch.

## Optional protection

Windows Local Administrator Password Solution (LAPS) manages administrator passwords. The optional backup control targets member servers running Server 2019 or later.

CAUTION: Enabling LAPS backup can start password rotation. Registry recovery cannot restore passwords that LAPS changes.

The LAPS control selects Active Directory backup. Applicable updates, directory schema, permissions, encryption, and password recovery require validation before application.

The LAPS control does not configure recovery passwords on domain controllers. Separate configuration and recovery checks remain required.

Local Security Authority (LSA) protection reduces access to the authentication process. The optional control targets Server 2025 without creating a firmware lock.

LSA protection requires extension checks, a restart, and runtime verification. Existing firmware locks require separate recovery review.

Windows PowerShell logging covers version 5.1. Logs can contain secrets, so protected logging, access restrictions, retention, and storage require validation.

The firewall control enables domain, private, and public profiles. Required allow rules and console access need validation before application.

These four controls require explicit selection and compatibility acceptance. They do not establish a complete Microsoft baseline.

## Local changes

Each apply command requires explicit control identifiers. Controls that can interrupt applications also require `-AcceptCompatibilityRisk`.

The recovery record captures the machine identity, original types, original values, and missing values. The tool saves this record before configuration writes.

1. Run `Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory C:\GPOScriptsRecovery -AcceptCompatibilityRisk -WhatIf` to preview a selected change.

CAUTION: Applying settings can interrupt authentication, network access, or applications. The example below belongs in an isolated lab first.

1. Run `Invoke-GpoLocalApply -Id LlmnrDisabled -BackupDirectory C:\GPOScriptsRecovery -AcceptCompatibilityRisk` after dependency validation.

The result identifies the recovery record. The tool never restarts the server automatically.

Recovery restores recorded values. It does not substitute weaker defaults. It refuses a different machine, a changed role, or conflicting later values.

CAUTION: Recovery can restore less restrictive settings. Application behavior can change again after recovery.

1. Run `Restore-GpoLocalState -Path C:\GPOScriptsRecovery\local-REPLACE-WITH-RECORDED-ID.json -WhatIf` with the actual recovery filename.
2. Run `Restore-GpoLocalState -Path C:\GPOScriptsRecovery\local-REPLACE-WITH-RECORDED-ID.json` with the same recovery filename after review.

Recovery removes values that were originally absent. It retains empty keys to protect unrelated settings. Feature recovery requires completed servicing.

A failed operation can leave partial changes. The error identifies the recovery record. Current values must match either the original or intended state.

Recovery records contain configuration details. Their integrity and access permissions require protection. Records are not cryptographically signed.

## Group Policy preparation

The tool creates unlinked Group Policy objects. It requires an explicit domain, domain controller, name, server version, and role.

The version and role select control definitions. They do not create scope filters. Scope selection and linking remain separate deployment steps.

1. Run `New-GpoConfiguration -Name 'LAB | Server 2022 signing' -Id SmbSigningRequired -Domain example.test -Server dc1.example.test -TargetVersion 2022 -Role MemberServer -BackupDirectory C:\GPOScriptsRecovery -AcceptCompatibilityRisk -WhatIf` to preview preparation.

CAUTION: The next command creates an object in Active Directory. It requires the intended lab domain and delegated permissions.

1. Run `New-GpoConfiguration -Name 'LAB | Server 2022 signing' -Id SmbSigningRequired -Domain example.test -Server dc1.example.test -TargetVersion 2022 -Role MemberServer -BackupDirectory C:\GPOScriptsRecovery -AcceptCompatibilityRisk` after replacing the lab target.

The tool writes registry policy values. It does not append registry preferences on each run.

Existing objects require `-UpdateExisting` and valid GPOScripts ownership metadata. The tool refuses linked objects and objects without its ownership metadata.

The tool backs up an existing object before changing it. Recovery validates the destination, backup files, and current object before restoration.

Recovery requires a matching completion record and an unchanged, unlinked object. Later settings, permissions, or report-visible filter changes block automatic restoration.

The recovery checks do not cover external filter definitions. Failed updates without a completion record require manual recovery from the preserved backup.

CAUTION: Group Policy recovery replaces settings with an earlier backup. It can remove changes from the selected operation.

1. Run `Restore-GpoConfiguration -ManifestPath C:\GPOScriptsRecovery\gpo-REPLACE-WITH-RECORDED-ID\recovery.json -WhatIf` with the actual manifest filename.
2. Run `Restore-GpoConfiguration -ManifestPath C:\GPOScriptsRecovery\gpo-REPLACE-WITH-RECORDED-ID\recovery.json` with the same manifest filename after review.

Recovery refuses automatic deletion of a newly created object. The unlinked object and its records remain available for review.

Registry policy values outside managed policy paths can persist after an object is unlinked. Restoring a policy object does not restore each endpoint.

Endpoint recovery requires recorded endpoint state or a separately validated corrective policy. Unlinking alone is not a recovery procedure.

## Existing filenames

Existing script filenames remain available as wrappers around the shared module.

- Local set scripts assess by default. They require `-Apply` for changes.
- Creation scripts show definitions by default. They require `-Create` and explicit target fields for changes.
- Rollback scripts require a recorded snapshot through `-Path`.
- The certificate and cipher wrappers only assess related evidence.
- The startup script assesses by default. Explicit changes run without prompts or automatic restart.

The default behavior has changed. Existing scheduled commands or startup policies require review before using version 2.

## Baselines and boundaries

Microsoft baselines remain the starting point for a complete configuration. This toolkit provides selected controls and evidence for comparison.

It does not import an entire baseline, change domain accounts, issue certificates, or establish application compatibility automatically.

The optional LAPS control can cause Windows to rotate local passwords. The other baseline checks provide advisory evidence only.

Some Microsoft pages describe different defaults. The toolkit records the observed state and avoids interpreting an absent value as proof of protection.

[Microsoft baseline toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)

## Tests

The test suite uses Pester 5.7.1. It replaces registry, feature, event, and domain operations with isolated substitutes.

The tests disable Pester's registry fixture. They do not require access to a live domain or writes to the Windows registry.

1. Run `Save-Module -Name Pester -RequiredVersion 5.7.1 -Path .\test-tools -Repository PSGallery` to obtain the test dependency.
2. Run `powershell.exe -NoProfile -File .\Tests\Invoke-Tests.ps1 -PesterPath .\test-tools\Pester\5.7.1\Pester.psd1` to test Windows PowerShell 5.1.
3. Run `pwsh.exe -NoProfile -File .\Tests\Invoke-Tests.ps1 -PesterPath .\test-tools\Pester\5.7.1\Pester.psd1` to test PowerShell 7.

The repository workflow runs both editions. Syntax and isolated tests do not replace server testing.

[Validation requirements](docs/Validation.md) cover all four server versions, both roles, policy processing, restarts, recovery, and application checks.

## Release status

Version 2 is a candidate for lab validation. Production deployment requires successful checks in the target environment.

No implementation test authorizes production deployment or proves effective protection on a server.
