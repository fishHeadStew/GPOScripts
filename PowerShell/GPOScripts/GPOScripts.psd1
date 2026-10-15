@{
    RootModule = 'GPOScripts.psm1'
    ModuleVersion = '2.0.0'
    GUID = '76918e6b-c87f-439e-94b2-46dd334d41dc'
    Author = 'GPOScripts contributors'
    Description = 'Assess and configure supported Windows servers with recorded recovery state.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-GpoControl', 'Get-GpoAssessment', 'Invoke-GpoLocalApply', 'Restore-GpoLocalState', 'New-GpoConfiguration', 'Restore-GpoConfiguration')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('Windows', 'GroupPolicy', 'Security'); LicenseUri = 'https://github.com/fishHeadStew/GPOScripts/blob/main/LICENSE'; ProjectUri = 'https://github.com/fishHeadStew/GPOScripts' } }
}
