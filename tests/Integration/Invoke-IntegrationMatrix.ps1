#Requires -Version 5

[CmdletBinding()]
param(
    [string]$RemoteComputer,
    [PSCredential]$Credential,
    [string]$KmsHost,
    [string]$DirectoryServer,
    [PSCredential]$DirectoryCredential,
    [switch]$AllowMutation,
    [string]$OutputPath = './integration-test-results.xml'
)

$matrixPath = Join-Path $PSScriptRoot 'IntegrationMatrix.psd1'
$testPath = Join-Path $PSScriptRoot 'IntegrationMatrix.Tests.ps1'
$matrix = Import-PowerShellDataFile $matrixPath

$previousEnvironment = @{
    RemoteComputer = $env:SLMGR_PS_TEST_REMOTE_COMPUTER
    KmsHost = $env:SLMGR_PS_TEST_KMS_HOST
    DirectoryServer = $env:SLMGR_PS_TEST_DIRECTORY_SERVER
    AllowMutation = $env:SLMGR_PS_TEST_ALLOW_MUTATION
}
$previousCredential = Get-Variable -Name SlmgrPsIntegrationCredential -Scope Global -ErrorAction SilentlyContinue
$previousDirectoryCredential = Get-Variable -Name SlmgrPsIntegrationDirectoryCredential -Scope Global -ErrorAction SilentlyContinue

try
{
    if ($PSBoundParameters.ContainsKey('RemoteComputer'))
    {
        $env:SLMGR_PS_TEST_REMOTE_COMPUTER = $RemoteComputer
    }
    if ($PSBoundParameters.ContainsKey('KmsHost'))
    {
        $env:SLMGR_PS_TEST_KMS_HOST = $KmsHost
    }
    if ($PSBoundParameters.ContainsKey('DirectoryServer'))
    {
        $env:SLMGR_PS_TEST_DIRECTORY_SERVER = $DirectoryServer
    }

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        Set-Variable -Name SlmgrPsIntegrationCredential -Scope Global -Value $Credential
    }
    else
    {
        Remove-Variable -Name SlmgrPsIntegrationCredential -Scope Global -ErrorAction Ignore
    }

    if ($PSBoundParameters.ContainsKey('DirectoryCredential'))
    {
        Set-Variable -Name SlmgrPsIntegrationDirectoryCredential -Scope Global -Value $DirectoryCredential
    }
    else
    {
        Remove-Variable -Name SlmgrPsIntegrationDirectoryCredential -Scope Global -ErrorAction Ignore
    }

    $env:SLMGR_PS_TEST_ALLOW_MUTATION = if ($AllowMutation.IsPresent) { '1' } else { $null }

    $availableInputs = @{
        RemoteComputer = -not [string]::IsNullOrWhiteSpace($env:SLMGR_PS_TEST_REMOTE_COMPUTER)
        Credential = $PSBoundParameters.ContainsKey('Credential')
        KmsHost = -not [string]::IsNullOrWhiteSpace($env:SLMGR_PS_TEST_KMS_HOST)
        DirectoryServer = -not [string]::IsNullOrWhiteSpace($env:SLMGR_PS_TEST_DIRECTORY_SERVER)
        DirectoryCredential = $PSBoundParameters.ContainsKey('DirectoryCredential')
        AllowMutation = $AllowMutation.IsPresent
    }

    $scenarioStatus = foreach ($scenario in $matrix.Scenarios)
    {
        $missingInputs = @(
            foreach ($requiredInput in $scenario.RequiredInputs)
            {
                if (-not $availableInputs[$requiredInput]) { $requiredInput }
            }
        )

        [PSCustomObject]@{
            Scenario = $scenario.Name
            Mode = if ($scenario.Tags -contains 'Destructive') { 'Destructive' } else { 'ReadOnly' }
            Ready = $missingInputs.Count -eq 0
            MissingInputs = $missingInputs -join ', '
            Coverage = $scenario.Coverage -join '; '
        }
    }

    $scenarioStatus | Format-Table -AutoSize

    $config = New-PesterConfiguration
    $config.Run.Path = $testPath
    $config.Filter.Tag = 'Integration'
    if (-not $AllowMutation.IsPresent)
    {
        $config.Filter.ExcludeTag = 'Destructive'
    }
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = $OutputPath

    $result = Invoke-Pester -Configuration $config
    if ($result.FailedCount -gt 0)
    {
        throw "Integration matrix failed with $($result.FailedCount) failed test(s)."
    }
}
finally
{
    $env:SLMGR_PS_TEST_REMOTE_COMPUTER = $previousEnvironment.RemoteComputer
    $env:SLMGR_PS_TEST_KMS_HOST = $previousEnvironment.KmsHost
    $env:SLMGR_PS_TEST_DIRECTORY_SERVER = $previousEnvironment.DirectoryServer
    $env:SLMGR_PS_TEST_ALLOW_MUTATION = $previousEnvironment.AllowMutation

    if ($null -ne $previousCredential)
    {
        Set-Variable -Name SlmgrPsIntegrationCredential -Scope Global -Value $previousCredential.Value
    }
    else
    {
        Remove-Variable -Name SlmgrPsIntegrationCredential -Scope Global -ErrorAction Ignore
    }

    if ($null -ne $previousDirectoryCredential)
    {
        Set-Variable -Name SlmgrPsIntegrationDirectoryCredential -Scope Global -Value $previousDirectoryCredential.Value
    }
    else
    {
        Remove-Variable -Name SlmgrPsIntegrationDirectoryCredential -Scope Global -ErrorAction Ignore
    }
}
