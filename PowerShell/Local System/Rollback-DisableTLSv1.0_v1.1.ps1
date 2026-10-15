<#
.SYNOPSIS
Restore values from a recorded local snapshot.
.DESCRIPTION
This script does not create inverse security settings. The shared module validates the snapshot and target.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$Path
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Path)) {
    throw 'Restoration requires -Path with a recorded snapshot.'
}
Import-Module (Join-Path $PSScriptRoot '..\GPOScripts\GPOScripts.psd1') -ErrorAction Stop
$arguments = @{ Path = $Path }
if ($PSBoundParameters.ContainsKey('WhatIf')) { $arguments.WhatIf = $PSBoundParameters['WhatIf'] }
if ($PSBoundParameters.ContainsKey('Confirm')) { $arguments.Confirm = $PSBoundParameters['Confirm'] }
Restore-GpoLocalState @arguments
