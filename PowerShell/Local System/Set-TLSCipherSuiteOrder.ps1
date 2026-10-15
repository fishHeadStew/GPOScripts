<#
.SYNOPSIS
Review baseline coverage without applying a custom cipher list.
.DESCRIPTION
This wrapper supports assessment only. It does not change registry values or create policy objects.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\GPOScripts\GPOScripts.psd1') -ErrorAction Stop
Get-GpoAssessment -Id 'BaselineCoverage'
