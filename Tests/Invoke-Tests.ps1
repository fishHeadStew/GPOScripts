#Requires -Version 5.1
[CmdletBinding()]
param([string]$PesterPath, [string]$OutputPath)
$ErrorActionPreference = 'Stop'
if ($PesterPath) { Import-Module $PesterPath -Force } else { Import-Module Pester -RequiredVersion 5.7.1 -Force }
$parseErrors = @()
Get-ChildItem -LiteralPath (Split-Path $PSScriptRoot -Parent) -Recurse -File |
    Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') } |
    ForEach-Object {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
        $parseErrors += @($errors)
    }
if ($parseErrors.Count) { $parseErrors | ForEach-Object { Write-Error $_.Message }; exit 1 }
$configuration = New-PesterConfiguration
$configuration.Run.Path = $PSScriptRoot
$configuration.Run.PassThru = $true
$configuration.TestRegistry.Enabled = $false
$configuration.Output.Verbosity = 'Detailed'
$result = Invoke-Pester -Configuration $configuration
if (-not $result) { throw 'The test framework did not return a result.' }
if ($OutputPath) {
    [pscustomobject]@{
        PowerShell=$PSVersionTable.PSVersion.ToString(); Pester=(Get-Module Pester).Version.ToString()
        Passed=$result.PassedCount; Failed=$result.FailedCount; Skipped=$result.SkippedCount
        FailedContainers=$result.FailedContainersCount
        Failures=@($result.Failed | ForEach-Object { [pscustomobject]@{Name=$_.ExpandedPath; Error=[string]$_.ErrorRecord} })
    } | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $OutputPath -Encoding utf8
}
if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0 -or $result.PassedCount -eq 0) { exit 1 }
