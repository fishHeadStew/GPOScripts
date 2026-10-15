BeforeAll {
    $script:entryPoint = Join-Path $PSScriptRoot '../Invoke-GPOScripts.ps1'
    function Get-GpoAssessment { [CmdletBinding()] param([string[]]$Id) }
    function Invoke-GpoLocalApply {
        [CmdletBinding(SupportsShouldProcess)] param([string[]]$Id, [string]$BackupDirectory, [switch]$AcceptCompatibilityRisk)
    }
}
Describe 'Command line boundary' {
    BeforeEach {
        Mock Import-Module {}
        Mock Get-GpoAssessment { [pscustomobject]@{Status='Assessed'} }
        Mock Invoke-GpoLocalApply { [pscustomobject]@{Status='Configured'; SnapshotPath='recorded-state.json'} }
    }
    It 'assesses by default' {
        & $script:entryPoint
        Should -Invoke Get-GpoAssessment -Times 1 -Exactly
        Should -Invoke Invoke-GpoLocalApply -Times 0 -Exactly
    }
    It 'rejects an existing report before applying settings' {
        $path = Join-Path $TestDrive 'existing.json'
        'existing' | Out-File -LiteralPath $path
        { & $script:entryPoint -Mode ApplyLocal -Id LlmnrDisabled -BackupDirectory $TestDrive -OutputPath $path } | Should -Throw '*already exists*'
        Should -Invoke Invoke-GpoLocalApply -Times 0 -Exactly
    }
    It 'rejects a missing report directory before applying settings' {
        { & $script:entryPoint -Mode ApplyLocal -Id LlmnrDisabled -BackupDirectory $TestDrive -OutputPath (Join-Path $TestDrive 'missing/report.json') } | Should -Throw '*directory does not exist*'
        Should -Invoke Invoke-GpoLocalApply -Times 0 -Exactly
    }
    It 'creates no report during WhatIf' {
        $path = Join-Path $TestDrive 'preview.json'
        & $script:entryPoint -OutputPath $path -WhatIf
        Test-Path -LiteralPath $path | Should -BeFalse
    }
}
