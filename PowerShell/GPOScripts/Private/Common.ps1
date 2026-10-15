function Get-GpoControl {
    [CmdletBinding()]
    param([string[]]$Id)
    $data = Import-PowerShellDataFile -LiteralPath (Join-Path $script:ModuleRoot 'Data/Controls.psd1')
    if ($data.SchemaVersion -ne 1) { throw 'The control catalogue has an unsupported version.' }
    $controls = @($data.Controls)
    $identifiers = @($controls | ForEach-Object { $_.Id })
    if (@($identifiers | Select-Object -Unique).Count -ne $controls.Count) { throw 'The control catalogue contains duplicate identifiers.' }
    foreach ($control in $controls) {
        foreach ($field in @('Id', 'Title', 'Kind', 'MinBuild', 'Roles', 'CompatibilityRisk', 'RestartRequired', 'Sources')) {
            if (-not $control.ContainsKey($field)) { throw "Control $($control.Id) is missing $field." }
        }
        if ($control.Kind -notin @('Registry', 'Feature', 'Audit')) { throw "Control $($control.Id) has an unsupported kind." }
        if ($control.Kind -eq 'Registry') {
            foreach ($setting in $control.Registry) {
                if ($setting.Path -notmatch '^HKLM:\\' -or $setting.Name -match '[\\/]' -or -not $setting.Name) {
                    throw "Control $($control.Id) contains an invalid registry location."
                }
                if ($setting.Type -notin @('DWord', 'String')) { throw "Control $($control.Id) has an unsupported value type." }
            }
        }
    }
    if ($PSBoundParameters.ContainsKey('Id')) {
        if (-not $Id -or @($Id | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) { throw 'Select at least one control.' }
        foreach ($item in $Id) {
            if ($item -notin $controls.Id) { throw "Unknown control: $item." }
        }
        $controls | Where-Object { $_.Id -in $Id }
    } else { $controls }
}

function Get-GpoTargetContext {
    [CmdletBinding()]
    param()
    if ($env:OS -ne 'Windows_NT') { throw 'Assessment requires Windows.' }
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $build = [int]$os.BuildNumber
    $versions = @{14393='2016'; 17763='2019'; 20348='2022'; 26100='2025'}
    $ends = @{'2016'=[datetime]'2027-01-12'; '2019'=[datetime]'2029-01-09'; '2022'=[datetime]'2031-10-14'; '2025'=[datetime]'2034-11-14'}
    $version = $versions[$build]
    $role = if ([int]$os.ProductType -eq 2) { 'DomainController' } elseif ([int]$os.ProductType -eq 3) { 'MemberServer' } else { 'Workstation' }
    $supported = ($null -ne $version -and $role -ne 'Workstation' -and [Environment]::Is64BitProcess)
    $reason = 'The server version and process architecture are supported.'
    if (-not $supported) { $reason = 'This tool requires a supported Windows Server build and a 64-bit PowerShell process.' }
    if ($supported -and [datetime]::UtcNow.Date -gt $ends[$version]) {
        $supported = $false
        $reason = 'This server version has reached the recorded end of support. Review the support matrix.'
    }
    $machine = Get-GpoRegistryState -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid
    if (-not $machine.ValueExists -or -not $machine.Value) { throw 'The machine identifier is unavailable.' }
    [pscustomobject]@{
        ComputerName = [string]$os.CSName
        MachineId = [string]$machine.Value
        Version = [string]$version
        Build = $build
        Role = $role
        Supported = $supported
        Reason = $reason
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

function Test-GpoControlApplicability {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Control, [Parameter(Mandatory)]$Context)
    $reason = 'The control applies to this server.'
    $applies = $true
    if (-not $Context.Supported) { $applies = $false; $reason = $Context.Reason }
    elseif ($Context.Role -notin $Control.Roles) { $applies = $false; $reason = 'The control does not apply to this server role.' }
    elseif ([int]$Context.Build -lt [int]$Control.MinBuild) { $applies = $false; $reason = 'The server build is older than the control requires.' }
    elseif ($Control.ContainsKey('MaxBuild') -and [int]$Context.Build -gt [int]$Control.MaxBuild) { $applies = $false; $reason = 'The server build is newer than this control supports.' }
    [pscustomobject]@{Applicable=$applies; Reason=$reason}
}

function New-GpoResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Control, [Parameter(Mandatory)][string]$Status, [Parameter(Mandatory)][string]$Reason, $Evidence)
    [pscustomobject]@{
        Id=$Control.Id; Title=$Control.Title; Status=$Status; Reason=$Reason
        Evidence=$Evidence; RestartRequired=[bool]$Control.RestartRequired
    }
}

function Write-GpoJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Path)
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $parent = [IO.Path]::GetDirectoryName($fullPath)
    if (-not [IO.Directory]::Exists($parent)) { $null = [IO.Directory]::CreateDirectory($parent) }
    # CreateNew preserves every prior recovery file. A failed write cannot authorize a mutation.
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($InputObject | ConvertTo-Json -Depth 30))
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Assert-GpoAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Apply and restore require an elevated PowerShell session.'
        }
    } finally { $identity.Dispose() }
}

function Test-GpoValuesEqual {
    param($Left, $Right)
    # JSON keeps scalar and array comparisons consistent in both supported PowerShell editions.
    return ((ConvertTo-Json -InputObject $Left -Compress -Depth 10) -ceq (ConvertTo-Json -InputObject $Right -Compress -Depth 10))
}
