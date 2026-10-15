<#
.SYNOPSIS
Assess the selected control. Changes require -Apply and a backup directory.
.DESCRIPTION
The shared module saves the original state before changes. The script never restarts Windows.
Use -WhatIf to preview an explicitly requested change.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [string]$BackupDirectory,
    [switch]$AcceptCompatibilityRisk
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\GPOScripts\GPOScripts.psd1') -ErrorAction Stop
$controlIds = @('Smb1ServerDisabled')
if (-not $Apply) {
    Get-GpoAssessment -Id $controlIds
    return
}
if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    throw 'Changes require -BackupDirectory.'
}
$arguments = @{
    Id = $controlIds
    BackupDirectory = $BackupDirectory
    AcceptCompatibilityRisk = $AcceptCompatibilityRisk
}
if ($PSBoundParameters.ContainsKey('WhatIf')) { $arguments.WhatIf = $PSBoundParameters['WhatIf'] }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Invoke-GpoLocalApply @arguments
