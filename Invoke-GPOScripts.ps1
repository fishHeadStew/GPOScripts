#Requires -Version 5.1
<#
.SYNOPSIS
Assesses supported Windows servers. Changes require an explicit mode.
.DESCRIPTION
Apply and restore require a selected target and a recovery location. The command never restarts a server or links a policy.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Assess', 'ApplyLocal', 'RestoreLocal', 'CreateGpo', 'RestoreGpo')][string]$Mode = 'Assess',
    [string[]]$Id,
    [string]$BackupDirectory,
    [string]$SnapshotPath,
    [string]$Name,
    [string]$Domain,
    [string]$Server,
    [ValidateSet('2016', '2019', '2022', '2025')][string]$TargetVersion,
    [ValidateSet('MemberServer', 'DomainController')][string]$Role,
    [switch]$UpdateExisting,
    [switch]$AcceptCompatibilityRisk,
    [string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($OutputPath) {
    if (Test-Path -LiteralPath $OutputPath) { throw 'The report path already exists. Select a new path.' }
    $outputFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($outputFullPath))) { throw 'The report directory does not exist.' }
}
Import-Module (Join-Path $PSScriptRoot 'PowerShell/GPOScripts/GPOScripts.psd1') -Force -ErrorAction Stop
$forward = @{WhatIf=$WhatIfPreference}
if ($PSBoundParameters.ContainsKey('Confirm')) { $forward.Confirm = $PSBoundParameters.Confirm }
switch ($Mode) {
    'Assess' {
        $argsForAssessment = @{}
        if ($PSBoundParameters.ContainsKey('Id')) { $argsForAssessment.Id = $Id }
        $result = @(Get-GpoAssessment @argsForAssessment)
    }
    'ApplyLocal' {
        if (-not $Id -or -not $BackupDirectory) { throw 'ApplyLocal requires -Id and -BackupDirectory.' }
        $result = Invoke-GpoLocalApply -Id $Id -BackupDirectory $BackupDirectory -AcceptCompatibilityRisk:$AcceptCompatibilityRisk @forward
    }
    'RestoreLocal' {
        if (-not $SnapshotPath) { throw 'RestoreLocal requires -SnapshotPath.' }
        $result = Restore-GpoLocalState -Path $SnapshotPath @forward
    }
    'CreateGpo' {
        if (-not $Id -or -not $Name -or -not $Domain -or -not $Server -or -not $TargetVersion -or -not $Role -or -not $BackupDirectory) {
            throw 'CreateGpo requires -Id, -Name, -Domain, -Server, -TargetVersion, -Role, and -BackupDirectory.'
        }
        $result = New-GpoConfiguration -Id $Id -Name $Name -Domain $Domain -Server $Server -TargetVersion $TargetVersion -Role $Role -BackupDirectory $BackupDirectory -UpdateExisting:$UpdateExisting -AcceptCompatibilityRisk:$AcceptCompatibilityRisk @forward
    }
    'RestoreGpo' {
        if (-not $SnapshotPath) { throw 'RestoreGpo requires -SnapshotPath.' }
        $result = Restore-GpoConfiguration -ManifestPath $SnapshotPath @forward
    }
}
if ($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath, 'Save the report')) {
    try { $result | ConvertTo-Json -Depth 30 | Out-File -LiteralPath $OutputPath -Encoding utf8 -NoClobber -ErrorAction Stop }
    catch {
        $result
        throw "The operation returned results, but report writing failed: $($_.Exception.Message)"
    }
}
$result
