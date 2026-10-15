<#
.SYNOPSIS
Review certificate authentication without obsolete enforcement switches.
.DESCRIPTION
This wrapper supports assessment only. It does not change registry values or create policy objects.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\GPOScripts\GPOScripts.psd1') -ErrorAction Stop
Get-GpoAssessment -Id 'CertificateReadiness'
