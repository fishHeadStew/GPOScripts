<#
.SYNOPSIS
Show control definitions. Creating an unlinked Group Policy object requires -Create.
.DESCRIPTION
The caller must select the domain, server, name, role, version, and backup directory.
The shared module backs up existing objects before an explicitly requested update.

#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Create,
    [string]$Name,
    [string]$Domain,
    [string]$Server,
    [ValidateSet('2016', '2019', '2022', '2025')]
    [string]$TargetVersion,
    [ValidateSet('MemberServer', 'DomainController')]
    [string]$Role,
    [string]$BackupDirectory,
    [switch]$UpdateExisting,
    [switch]$AcceptCompatibilityRisk
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\GPOScripts\GPOScripts.psd1') -ErrorAction Stop
$controlIds = @('LdapClientSigningRequired', 'LdapServerSigningRequired', 'LdapServerSigningEnforced', 'LdapChannelBindingRequired')
if (-not $Create) {
    Get-GpoControl -Id $controlIds
    return
}
foreach ($required in @('Name', 'Domain', 'Server', 'TargetVersion', 'Role', 'BackupDirectory')) {
    if ([string]::IsNullOrWhiteSpace([string]$PSBoundParameters[$required])) {
        throw "Creating a Group Policy object requires -$required."
    }
}
$builds = @{ '2016' = 14393; '2019' = 17763; '2022' = 20348; '2025' = 26100 }
$targetBuild = $builds[$TargetVersion]
$definitions = @(Get-GpoControl -Id $controlIds)
$selectedControls = @($definitions | Where-Object {
    $_.Roles -contains $Role -and $_.MinBuild -le $targetBuild -and
    (-not $_.ContainsKey('MaxBuild') -or $_.MaxBuild -ge $targetBuild)
})
if ($selectedControls.Count -eq 0) {
    throw 'No controls in this wrapper apply to the selected role and version.'
}
$arguments = @{
    Name = $Name
    Id = @($selectedControls | ForEach-Object { $_.Id })
    Domain = $Domain
    Server = $Server
    TargetVersion = $TargetVersion
    Role = $Role
    BackupDirectory = $BackupDirectory
    UpdateExisting = $UpdateExisting
    AcceptCompatibilityRisk = $AcceptCompatibilityRisk
}
if ($PSBoundParameters.ContainsKey('WhatIf')) { $arguments.WhatIf = $PSBoundParameters['WhatIf'] }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
New-GpoConfiguration @arguments
