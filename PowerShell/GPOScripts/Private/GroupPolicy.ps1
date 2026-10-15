function Initialize-GpoGroupPolicy {
    [CmdletBinding()]
    param()
    if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    foreach ($command in @('Get-GPO', 'New-GPO', 'Backup-GPO', 'Restore-GPO', 'Get-GPOReport', 'Get-GPRegistryValue', 'Set-GPRegistryValue')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "The GroupPolicy command $command is unavailable." }
    }
}

function Get-GpoDestinationInventory {
    [CmdletBinding()]
    param([string]$Domain, [string]$Server)
    foreach ($value in @($Domain, $Server)) {
        if ($value -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') { throw 'Specify a DNS domain and a DNS server name.' }
    }
    $inventory = @(Get-GPO -All -Domain $Domain -Server $Server -ErrorAction Stop)
    if ($inventory.Count -eq 0) { throw 'The destination returned no GPOs. Its identity could not be verified.' }
    foreach ($gpo in $inventory) {
        if ([string]$gpo.DomainName -ine $Domain) { throw 'The returned GPO domain does not match the requested domain.' }
    }
    return $inventory
}

function Read-GpoOwnership {
    [CmdletBinding()]
    param([object]$Gpo)
    $prefix = 'GPOScripts:v1:'
    $description = [string]$Gpo.Description
    if (-not $description.StartsWith($prefix, [StringComparison]::Ordinal)) { throw 'The GPO has no GPOScripts ownership metadata.' }
    try { $metadata = $description.Substring($prefix.Length) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'The GPO ownership metadata is invalid.' }
    $ownerId = [guid]::Empty
    if ($metadata.SchemaVersion -ne 1 -or $metadata.Product -ne 'GPOScripts' -or
        -not [guid]::TryParse([string]$metadata.OwnershipId, [ref]$ownerId) -or $ownerId -eq [guid]::Empty -or
        [string]$metadata.Domain -ine [string]$Gpo.DomainName -or [string]$metadata.Name -cne [string]$Gpo.DisplayName -or
        [string]$metadata.TargetVersion -notin @('2016', '2019', '2022', '2025') -or
        [string]$metadata.Role -notin @('MemberServer', 'DomainController')) { throw 'The GPO ownership metadata does not match its identity.' }
    return $metadata
}

function Get-GpoSafeReport {
    [CmdletBinding()]
    param([guid]$Guid, [string]$Domain, [string]$Server)
    $text = Get-GPOReport -Guid $Guid -Domain $Domain -Server $Server -ReportType Xml -ErrorAction Stop
    $document = New-Object System.Xml.XmlDocument
    $document.XmlResolver = $null
    try { $document.LoadXml([string]$text) } catch { throw 'The GPO report is not valid XML.' }
    if ($document.DocumentType -or -not $document.SelectSingleNode('/*[local-name()="GPO"]')) { throw 'The GPO report has an unexpected format.' }
    $identifier = $document.SelectSingleNode('/*[local-name()="GPO"]/*[local-name()="Identifier"]/*[local-name()="Identifier"]')
    $reportDomain = $document.SelectSingleNode('/*[local-name()="GPO"]/*[local-name()="Identifier"]/*[local-name()="Domain"]')
    $reportId = [guid]::Empty
    if (-not $identifier -or -not [guid]::TryParse($identifier.InnerText, [ref]$reportId) -or $reportId -ne $Guid -or
        -not $reportDomain -or $reportDomain.InnerText -ine $Domain) { throw 'The GPO report does not match the requested destination.' }
    if ($document.SelectNodes('/*[local-name()="GPO"]/*[local-name()="LinksTo"]').Count -gt 0) {
        throw 'The GPO has links. This command only changes unlinked GPOs.'
    }
    return ,$document
}

function Get-GpoReportStateHash {
    [CmdletBinding()]
    param([System.Xml.XmlDocument]$Report)
    $security = $Report.SelectSingleNode('/*[local-name()="GPO"]/*[local-name()="SecurityDescriptor"]')
    $filterData = $Report.SelectSingleNode('/*[local-name()="GPO"]/*[local-name()="FilterDataAvailable"]')
    if (-not $security -or -not $security.HasChildNodes -or -not $filterData -or $filterData.InnerText -ne 'true') {
        throw 'The GPO report lacks complete permission or filter metadata.'
    }
    # Preserve all report-visible state, including SecurityDescriptor and FilterName/FilterDescription.
    # External WMI filter objects are not fully represented by this report.
    $stable = $Report.CloneNode($true)
    $volatile = $stable.SelectNodes('/*[local-name()="GPO"]/*[local-name()="CreatedTime" or local-name()="ModifiedTime" or local-name()="ReadTime"] | /*[local-name()="GPO"]/*[local-name()="Computer" or local-name()="User"]/*[local-name()="VersionDirectory" or local-name()="VersionSysvol"]')
    foreach ($node in @($volatile)) { $node.ParentNode.RemoveChild($node) | Out-Null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stable.DocumentElement.OuterXml)))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Write-GpoCompletion {
    [CmdletBinding()]
    param([string]$ManifestPath, [object]$Manifest, [System.Xml.XmlDocument]$Report)
    $record = [ordered]@{
        SchemaVersion = 1; Product = 'GPOScripts'; Operation = 'GpoConfigurationCompletion'; FingerprintScope = 'ReportStateV1'
        CompletedUtc = [DateTime]::UtcNow.ToString('o'); RunId = $Manifest.RunId; GpoId = $Manifest.GpoId; OwnershipId = $Manifest.OwnershipId
        ManifestSHA256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256 -ErrorAction Stop).Hash
        ExpectedReportHash = Get-GpoReportStateHash -Report $Report
    }
    Write-GpoJson -InputObject $record -Path (Join-Path ([IO.Path]::GetDirectoryName($ManifestPath)) 'completion.json') | Out-Null
}

function Read-GpoCompletion {
    [CmdletBinding()]
    param([System.IO.FileInfo]$ManifestFile, [object]$Manifest)
    $path = Join-Path $ManifestFile.DirectoryName 'completion.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop)) {
        throw 'The completion record is absent. Automatic restore is refused. Review the preserved backup for manual recovery.'
    }
    $file = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The completion record must not be a link.' }
    try { $record = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'The completion record is invalid.' }
    if ($record.SchemaVersion -ne 1 -or $record.Product -ne 'GPOScripts' -or $record.Operation -ne 'GpoConfigurationCompletion' -or
        $record.FingerprintScope -ne 'ReportStateV1' -or [string]$record.RunId -cne [string]$Manifest.RunId -or
        [string]$record.GpoId -cne [string]$Manifest.GpoId -or [string]$record.OwnershipId -cne [string]$Manifest.OwnershipId -or
        [string]$record.ExpectedReportHash -notmatch '^[0-9A-Fa-f]{64}$' -or
        [string]$record.ManifestSHA256 -ine (Get-FileHash -LiteralPath $ManifestFile.FullName -Algorithm SHA256 -ErrorAction Stop).Hash) {
        throw 'The completion record does not match the recovery manifest.'
    }
    return $record
}

function Assert-GpoOwnedIdentity {
    [CmdletBinding()]
    param([object]$Gpo, [string]$Name, [string]$Domain, [guid]$Guid, [string]$OwnershipId, [string]$TargetVersion, [string]$Role)
    if ([guid]$Gpo.Id -ne $Guid -or [string]$Gpo.DomainName -ine $Domain -or [string]$Gpo.DisplayName -cne $Name) {
        throw 'The GPO identity changed. No further changes are allowed.'
    }
    $owner = Read-GpoOwnership -Gpo $Gpo
    if ([string]$owner.OwnershipId -cne $OwnershipId -or [string]$owner.TargetVersion -ne $TargetVersion -or [string]$owner.Role -ne $Role) {
        throw 'The GPO ownership or target profile does not match.'
    }
}

function Get-GpoBackupFileRecord {
    [CmdletBinding()]
    param([string]$Path)
    $root = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $rootItem = Get-Item -LiteralPath $root -ErrorAction Stop
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The GPO backup directory is a link.' }
    $items = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop)
    if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) { throw 'The GPO backup contains a linked item.' }
    $files = @($items | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)
    if ($files.Count -eq 0) { throw 'The GPO backup contains no files.' }
    foreach ($file in $files) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The GPO backup contains a linked file.' }
        [pscustomobject]@{ RelativePath = $file.FullName.Substring($root.Length); SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
    }
}

function Get-GpoPolicyRegistryState {
    [CmdletBinding()]
    param([guid]$Guid, [string]$Domain, [string]$Server, [object]$Setting)
    try {
        $values = @(Get-GPRegistryValue -Guid $Guid -Domain $Domain -Server $Server -Key $Setting.Key -ValueName $Setting.Name -ErrorAction Stop)
    } catch {
        # Do not treat access, transport, input-validation, or unknown errors as an absent value.
        $missingId = 'UnableToRetrievePolicyRegistryItem,Microsoft.GroupPolicy.Commands.GetGPRegistryValueCommand'
        if ($_.FullyQualifiedErrorId -eq $missingId -and $_.Exception -is [ArgumentException] -and
            $_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::InvalidArgument -and
            $_.Exception.ParamName -in @('keyPath', 'valueName')) {
            return [pscustomobject]@{ Exists = $false; Matches = $false }
        }
        throw
    }
    if ($values.Count -ne 1) { throw 'The registry policy read returned an unexpected result count.' }
    $actual = $values[0]
    $matches = ([string]$actual.PolicyState -eq 'Set' -and $actual.HasValue -and
        [string]$actual.Type -ieq [string]$Setting.Type -and [string]$actual.Value -ceq [string]$Setting.Value)
    return [pscustomobject]@{ Exists = $true; Matches = [bool]$matches }
}

function Assert-GpoRecoveryPath {
    [CmdletBinding()]
    param([string]$RunDirectory)
    # Leave room for the backup GUID and the standard registry-policy backup tree on PowerShell 5.1.
    if ((Join-Path $RunDirectory 'Backup').Length -gt 180) {
        throw 'The recovery path is too long for Windows PowerShell 5.1. Select a shorter backup directory.'
    }
}

function Get-GpoSupportDate {
    [CmdletBinding()]
    param()
    return [DateTime]::UtcNow.Date
}

function New-GpoConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string[]]$Id,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Domain,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Server,
        [Parameter(Mandatory = $true)][ValidateSet('2016', '2019', '2022', '2025')][string]$TargetVersion,
        [Parameter(Mandatory = $true)][ValidateSet('MemberServer', 'DomainController')][string]$Role,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$BackupDirectory,
        [switch]$UpdateExisting,
        [switch]$AcceptCompatibilityRisk
    )
    $ErrorActionPreference = 'Stop'
    $builds = @{ '2016' = 14393; '2019' = 17763; '2022' = 20348; '2025' = 26100 }
    $supportEnds = @{ '2016' = [datetime]'2027-01-12'; '2019' = [datetime]'2029-01-09'; '2022' = [datetime]'2031-10-14'; '2025' = [datetime]'2034-11-14' }
    if ((Get-GpoSupportDate) -gt $supportEnds[$TargetVersion]) {
        throw "Windows Server $TargetVersion is unsupported after its recorded support date, $($supportEnds[$TargetVersion].ToString('yyyy-MM-dd')). Review the support matrix."
    }
    $context = [pscustomobject]@{ Version = $TargetVersion; Build = $builds[$TargetVersion]; Role = $Role; Supported = $true }
    $controls = @(Get-GpoControl -Id $Id)
    if ($controls.Count -eq 0) { throw 'Select at least one registry control.' }
    $settings = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    foreach ($control in $controls) {
        if ($control.Kind -ne 'Registry') { throw "Control $($control.Id) cannot become a registry policy." }
        $applicability = Test-GpoControlApplicability -Control $control -Context $context
        if (-not $applicability.Applicable) { throw "Control $($control.Id) does not apply: $($applicability.Reason)" }
        if ($control.CompatibilityRisk -and -not $AcceptCompatibilityRisk -and -not $WhatIfPreference) {
            throw "Control $($control.Id) requires AcceptCompatibilityRisk."
        }
        if (@($control.Registry).Count -eq 0) { throw "Control $($control.Id) has no registry settings." }
        foreach ($setting in $control.Registry) {
            if ([string]$setting.Path -notmatch '^HKLM:\\' -or [string]$setting.Type -notin @('DWord', 'String') -or [string]::IsNullOrEmpty([string]$setting.Name)) {
                throw "Control $($control.Id) has an unsupported registry setting."
            }
            $key = ([string]$setting.Path -replace '^HKLM:', 'HKLM')
            $identity = $key + '|' + [string]$setting.Name
            if ($seen.ContainsKey($identity)) { throw 'Selected controls contain a duplicate registry value.' }
            $seen[$identity] = $true
            $settings.Add([pscustomobject]@{ Key = $key; Name = [string]$setting.Name; Type = [string]$setting.Type; Value = $setting.Value; ControlId = [string]$control.Id })
        }
    }
    Initialize-GpoGroupPolicy
    $inventory = @(Get-GpoDestinationInventory -Domain $Domain -Server $Server)
    $matches = @($inventory | Where-Object { $_.DisplayName -ieq $Name })
    if ($matches.Count -gt 1) { throw 'The GPO name is ambiguous.' }
    $existing = $null
    $priorReport = $null
    $owner = $null
    if ($matches.Count -eq 1) {
        if (-not $UpdateExisting) { throw 'The GPO already exists. UpdateExisting is required.' }
        $existing = $matches[0]
        $owner = Read-GpoOwnership -Gpo $existing
        Assert-GpoOwnedIdentity -Gpo $existing -Name $Name -Domain $Domain -Guid $existing.Id -OwnershipId $owner.OwnershipId -TargetVersion $TargetVersion -Role $Role
        $priorReport = Get-GpoSafeReport -Guid $existing.Id -Domain $Domain -Server $Server
        $changes = New-Object 'System.Collections.Generic.List[object]'
        foreach ($setting in $settings) {
            $state = Get-GpoPolicyRegistryState -Guid $existing.Id -Domain $Domain -Server $Server -Setting $setting
            if (-not $state.Matches) { $changes.Add($setting) }
        }
        if ($changes.Count -eq 0) {
            Get-GpoSafeReport -Guid $existing.Id -Domain $Domain -Server $Server | Out-Null
            return [pscustomobject]@{ Status = 'Unchanged'; Name = $Name; GpoId = [guid]$existing.Id; Domain = $Domain; Server = $Server; ManifestPath = $null; Created = $false; TargetVersion = $TargetVersion; Role = $Role }
        }
        $settings = $changes
    }
    if (-not $PSCmdlet.ShouldProcess("$Domain / $Server / $Name", 'Write registry settings to an unlinked GPO')) { return }
    $runId = [guid]::NewGuid().ToString('D')
    $runDirectory = Join-Path ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupDirectory)) ('gpo-' + $runId.Replace('-', '').Substring(0, 12))
    Assert-GpoRecoveryPath -RunDirectory $runDirectory
    New-Item -Path $runDirectory -ItemType Directory -ErrorAction Stop | Out-Null
    $backupPath = Join-Path $runDirectory 'Backup'
    $manifestPath = Join-Path $runDirectory 'recovery.json'
    $isExisting = $null -ne $existing
    if (-not $owner) {
        $owner = [pscustomobject]@{ SchemaVersion = 1; Product = 'GPOScripts'; OwnershipId = [guid]::NewGuid().ToString('D'); Domain = $Domain; Name = $Name; TargetVersion = $TargetVersion; Role = $Role }
    }
    $manifest = [ordered]@{
        SchemaVersion = 1; Product = 'GPOScripts'; Operation = 'GpoConfiguration'; RunId = $runId
        CreatedUtc = [DateTime]::UtcNow.ToString('o'); Domain = $Domain; Server = $Server; Name = $Name
        TargetVersion = $TargetVersion; Role = $Role; OwnershipId = [string]$owner.OwnershipId
        RecoveryMode = 'ManualRetainNewGpo'; GpoId = $null; BackupId = $null; BackupPath = $null
        BackupFiles = @(); PriorReportHash = $null; Controls = @($controls | ForEach-Object { $_.Id }); Settings = @($settings.ToArray())
    }
    if ($isExisting) {
        $fresh = Get-GPO -Guid $existing.Id -Domain $Domain -Server $Server -ErrorAction Stop
        Assert-GpoOwnedIdentity -Gpo $fresh -Name $Name -Domain $Domain -Guid $existing.Id -OwnershipId $owner.OwnershipId -TargetVersion $TargetVersion -Role $Role
        $priorReport = Get-GpoSafeReport -Guid $existing.Id -Domain $Domain -Server $Server
        New-Item -Path $backupPath -ItemType Directory -ErrorAction Stop | Out-Null
        $backup = Backup-GPO -Guid $existing.Id -Domain $Domain -Server $Server -Path $backupPath -Comment ('GPOScripts ' + $runId) -ErrorAction Stop
        $backupId = [guid]::Empty
        if (-not [guid]::TryParse([string]$backup.Id, [ref]$backupId) -or $backupId -eq [guid]::Empty -or
            [guid]$backup.GpoId -ne [guid]$existing.Id -or [string]$backup.DomainName -ine $Domain) { throw 'The GPO backup identity does not match.' }
        $manifest.RecoveryMode = 'RestoreExistingBackup'
        $manifest.GpoId = ([guid]$existing.Id).ToString('D')
        $manifest.BackupId = $backupId.ToString('D')
        $manifest.BackupPath = $backupPath
        $manifest.BackupFiles = @(Get-GpoBackupFileRecord -Path $backupPath)
        $manifest.PriorReportHash = Get-GpoReportStateHash -Report $priorReport
        Write-GpoJson -InputObject $manifest -Path $manifestPath | Out-Null
        $gpo = $fresh
    } else {
        Write-GpoJson -InputObject $manifest -Path (Join-Path $runDirectory 'intent.json') | Out-Null
        $description = 'GPOScripts:v1:' + ($owner | ConvertTo-Json -Compress -Depth 5)
        $gpo = New-GPO -Name $Name -Domain $Domain -Server $Server -Comment $description -ErrorAction Stop
        $manifest.GpoId = ([guid]$gpo.Id).ToString('D')
        Write-GpoJson -InputObject $manifest -Path $manifestPath | Out-Null
    }
    try {
        $gpoId = [guid]$manifest.GpoId
        $fresh = Get-GPO -Guid $gpoId -Domain $Domain -Server $Server -ErrorAction Stop
        Assert-GpoOwnedIdentity -Gpo $fresh -Name $Name -Domain $Domain -Guid $gpoId -OwnershipId $owner.OwnershipId -TargetVersion $TargetVersion -Role $Role
        Get-GpoSafeReport -Guid $gpoId -Domain $Domain -Server $Server | Out-Null
        foreach ($setting in $settings) {
            Get-GpoSafeReport -Guid $gpoId -Domain $Domain -Server $Server | Out-Null
            Set-GPRegistryValue -Guid $gpoId -Domain $Domain -Server $Server -Key $setting.Key -ValueName $setting.Name -Type $setting.Type -Value $setting.Value -ErrorAction Stop | Out-Null
            $actual = Get-GPRegistryValue -Guid $gpoId -Domain $Domain -Server $Server -Key $setting.Key -ValueName $setting.Name -ErrorAction Stop
            if (@($actual).Count -ne 1 -or [string]$actual.PolicyState -ne 'Set' -or -not $actual.HasValue -or
                [string]$actual.Type -ine $setting.Type -or [string]$actual.Value -cne [string]$setting.Value) {
                throw "Verification failed for control $($setting.ControlId)."
            }
        }
        $completedReport = Get-GpoSafeReport -Guid $gpoId -Domain $Domain -Server $Server
        Write-GpoCompletion -ManifestPath $manifestPath -Manifest $manifest -Report $completedReport
        [pscustomobject]@{ Status = 'ConfiguredUnlinked'; Name = $Name; GpoId = $gpoId; Domain = $Domain; Server = $Server; ManifestPath = $manifestPath; Created = -not $isExisting; TargetVersion = $TargetVersion; Role = $Role }
    } catch { throw "GPO configuration stopped. Recovery manifest: $manifestPath. $($_.Exception.Message)" }
}

function Restore-GpoConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ManifestPath)
    $ErrorActionPreference = 'Stop'
    $manifestFile = Get-Item -LiteralPath $ManifestPath -ErrorAction Stop
    if ($manifestFile.PSIsContainer -or ($manifestFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Specify a recovery manifest file.' }
    try { $manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'The recovery manifest is not valid JSON.' }
    if ($manifest.SchemaVersion -ne 1 -or $manifest.Product -ne 'GPOScripts' -or $manifest.Operation -ne 'GpoConfiguration') { throw 'The recovery manifest schema is unsupported.' }
    if ($manifest.RecoveryMode -eq 'ManualRetainNewGpo') { throw 'This operation created a GPO. Automatic deletion is refused. Review the retained unlinked GPO manually.' }
    if ($manifest.RecoveryMode -ne 'RestoreExistingBackup') { throw 'The recovery manifest has an unsupported recovery mode.' }
    foreach ($property in @('GpoId', 'BackupId', 'OwnershipId', 'RunId')) {
        $parsed = [guid]::Empty
        if (-not [guid]::TryParse([string]$manifest.$property, [ref]$parsed) -or $parsed -eq [guid]::Empty) { throw "The manifest $property is invalid." }
    }
    if ([string]$manifest.TargetVersion -notin @('2016', '2019', '2022', '2025') -or [string]$manifest.Role -notin @('MemberServer', 'DomainController') -or
        [string]::IsNullOrWhiteSpace([string]$manifest.Name) -or [string]$manifest.PriorReportHash -notmatch '^[0-9A-Fa-f]{64}$') { throw 'The recovery target metadata is invalid.' }
    $completion = Read-GpoCompletion -ManifestFile $manifestFile -Manifest $manifest
    $expectedBackupPath = [IO.Path]::GetFullPath((Join-Path $manifestFile.DirectoryName 'Backup'))
    if ([string]::IsNullOrWhiteSpace([string]$manifest.BackupPath) -or [IO.Path]::GetFullPath([string]$manifest.BackupPath) -ine $expectedBackupPath) { throw 'The backup path does not belong to this recovery manifest.' }
    $actualFiles = @(Get-GpoBackupFileRecord -Path $expectedBackupPath)
    $expectedFiles = @($manifest.BackupFiles)
    if ($actualFiles.Count -ne $expectedFiles.Count) { throw 'The backup file count changed.' }
    foreach ($file in $actualFiles) {
        $expected = @($expectedFiles | Where-Object { $_.RelativePath -ceq $file.RelativePath })
        if ($expected.Count -ne 1 -or [string]$expected[0].SHA256 -ine [string]$file.SHA256) { throw 'A backup file failed integrity verification.' }
    }
    Initialize-GpoGroupPolicy
    Get-GpoDestinationInventory -Domain $manifest.Domain -Server $manifest.Server | Out-Null
    $gpo = Get-GPO -Guid ([guid]$manifest.GpoId) -Domain $manifest.Domain -Server $manifest.Server -ErrorAction Stop
    Assert-GpoOwnedIdentity -Gpo $gpo -Name $manifest.Name -Domain $manifest.Domain -Guid ([guid]$manifest.GpoId) -OwnershipId $manifest.OwnershipId -TargetVersion $manifest.TargetVersion -Role $manifest.Role
    $currentReport = Get-GpoSafeReport -Guid ([guid]$manifest.GpoId) -Domain $manifest.Domain -Server $manifest.Server
    if ((Get-GpoReportStateHash -Report $currentReport) -ine [string]$completion.ExpectedReportHash) {
        throw 'The GPO changed after the recorded operation. Automatic restore is refused to preserve later edits.'
    }
    if (-not $PSCmdlet.ShouldProcess("$($manifest.Domain) / $($manifest.Server) / $($manifest.Name)", 'Restore the recorded GPO backup')) { return }
    $currentReport = Get-GpoSafeReport -Guid ([guid]$manifest.GpoId) -Domain $manifest.Domain -Server $manifest.Server
    if ((Get-GpoReportStateHash -Report $currentReport) -ine [string]$completion.ExpectedReportHash) { throw 'The GPO changed before restoration.' }
    $restoreRunId = [guid]::NewGuid().ToString('D')
    $preservedDirectory = Join-Path $manifestFile.Directory.Parent.FullName ('gpr-' + $restoreRunId.Replace('-', '').Substring(0, 12))
    Assert-GpoRecoveryPath -RunDirectory $preservedDirectory
    $preservedBackupPath = Join-Path $preservedDirectory 'Backup'
    New-Item -Path $preservedBackupPath -ItemType Directory -ErrorAction Stop | Out-Null
    $preserved = Backup-GPO -Guid ([guid]$manifest.GpoId) -Domain $manifest.Domain -Server $manifest.Server -Path $preservedBackupPath -Comment ('GPOScripts before restore ' + $restoreRunId) -ErrorAction Stop
    $preservedId = [guid]::Empty
    if (-not [guid]::TryParse([string]$preserved.Id, [ref]$preservedId) -or $preservedId -eq [guid]::Empty -or
        [guid]$preserved.GpoId -ne [guid]$manifest.GpoId -or [string]$preserved.DomainName -ine [string]$manifest.Domain) { throw 'The backup before restoration has an unexpected identity.' }
    $preservedManifest = [ordered]@{
        SchemaVersion = 1; Product = 'GPOScripts'; Operation = 'GpoConfiguration'; RunId = $restoreRunId
        CreatedUtc = [DateTime]::UtcNow.ToString('o'); Domain = $manifest.Domain; Server = $manifest.Server; Name = $manifest.Name
        TargetVersion = $manifest.TargetVersion; Role = $manifest.Role; OwnershipId = $manifest.OwnershipId
        RecoveryMode = 'RestoreExistingBackup'; GpoId = $manifest.GpoId; BackupId = $preservedId.ToString('D'); BackupPath = $preservedBackupPath
        BackupFiles = @(Get-GpoBackupFileRecord -Path $preservedBackupPath); PriorReportHash = (Get-GpoReportStateHash -Report $currentReport)
        Controls = @(); Settings = @(); Reason = 'Preserve the state before restoring an older backup.'
    }
    $preservedManifestPath = Join-Path $preservedDirectory 'recovery.json'
    Write-GpoJson -InputObject $preservedManifest -Path $preservedManifestPath | Out-Null
    $attempt = [ordered]@{ SchemaVersion = 1; Product = 'GPOScripts'; Operation = 'RestoreGpoConfiguration'; CreatedUtc = [DateTime]::UtcNow.ToString('o'); ManifestPath = $manifestFile.FullName; GpoId = $manifest.GpoId; BackupId = $manifest.BackupId; Domain = $manifest.Domain; Server = $manifest.Server; PreservedManifestPath = $preservedManifestPath }
    Write-GpoJson -InputObject $attempt -Path (Join-Path $manifestFile.DirectoryName ('restore-' + [guid]::NewGuid().ToString('D') + '.json')) | Out-Null
    $lastReport = Get-GpoSafeReport -Guid ([guid]$manifest.GpoId) -Domain $manifest.Domain -Server $manifest.Server
    if ((Get-GpoReportStateHash -Report $lastReport) -ine [string]$completion.ExpectedReportHash) { throw 'The GPO changed while creating the backup before restoration.' }
    Restore-GPO -BackupId ([guid]$manifest.BackupId) -Path $expectedBackupPath -Domain $manifest.Domain -Server $manifest.Server -ErrorAction Stop | Out-Null
    $restored = Get-GPO -Guid ([guid]$manifest.GpoId) -Domain $manifest.Domain -Server $manifest.Server -ErrorAction Stop
    Assert-GpoOwnedIdentity -Gpo $restored -Name $manifest.Name -Domain $manifest.Domain -Guid ([guid]$manifest.GpoId) -OwnershipId $manifest.OwnershipId -TargetVersion $manifest.TargetVersion -Role $manifest.Role
    $report = Get-GpoSafeReport -Guid ([guid]$manifest.GpoId) -Domain $manifest.Domain -Server $manifest.Server
    if ((Get-GpoReportStateHash -Report $report) -ine [string]$manifest.PriorReportHash) { throw 'GPO restoration completed, but settings verification failed.' }
    Write-GpoCompletion -ManifestPath $preservedManifestPath -Manifest $preservedManifest -Report $report
    [pscustomobject]@{ Status = 'RestoredUnlinked'; Name = $manifest.Name; GpoId = [guid]$manifest.GpoId; Domain = $manifest.Domain; Server = $manifest.Server; ManifestPath = $manifestFile.FullName; PreservedManifestPath = $preservedManifestPath }
}
