<#
.SYNOPSIS
Assess the selected control. Changes require -Apply and a backup directory.
.DESCRIPTION
The shared module saves the original state before changes. The script never restarts Windows.
Startup execution does not prompt. The caller must provide every required parameter.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [string]$BackupDirectory,
    [switch]$AcceptCompatibilityRisk
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\GPOScripts\GPOScripts.psd1') -ErrorAction Stop
$controlIds = @('PowerShell2Disabled')
if (-not $Apply) {
    Get-GpoAssessment -Id $controlIds
    return
}
if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
    throw 'Changes require -BackupDirectory.'
}
if ($PSBoundParameters.ContainsKey('Confirm') -and $PSBoundParameters['Confirm']) {
    throw 'Startup execution cannot request confirmation prompts.'
}
$arguments = @{
    Id = $controlIds
    BackupDirectory = $BackupDirectory
    AcceptCompatibilityRisk = $AcceptCompatibilityRisk
}
if ($PSBoundParameters.ContainsKey('WhatIf')) { $arguments.WhatIf = $PSBoundParameters['WhatIf'] }
$arguments.Confirm = $false
Invoke-GpoLocalApply @arguments
