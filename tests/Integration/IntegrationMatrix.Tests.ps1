$hasRemoteComputer = -not [string]::IsNullOrWhiteSpace($env:SLMGR_PS_TEST_REMOTE_COMPUTER)
$hasKmsHost = -not [string]::IsNullOrWhiteSpace($env:SLMGR_PS_TEST_KMS_HOST)
$hasDirectoryServer = -not [string]::IsNullOrWhiteSpace($env:SLMGR_PS_TEST_DIRECTORY_SERVER)
$hasCredential = $null -ne (Get-Variable -Name SlmgrPsIntegrationCredential -Scope Global -ErrorAction SilentlyContinue)
$hasDirectoryCredential = $null -ne (Get-Variable -Name SlmgrPsIntegrationDirectoryCredential -Scope Global -ErrorAction SilentlyContinue)
$allowMutation = $env:SLMGR_PS_TEST_ALLOW_MUTATION -eq '1'

BeforeAll {
    Import-Module $PSScriptRoot/../../src/slmgr-ps.psd1 -Force

    $script:RemoteComputer = $env:SLMGR_PS_TEST_REMOTE_COMPUTER
    $script:KmsHost = $env:SLMGR_PS_TEST_KMS_HOST
    $script:DirectoryServer = $env:SLMGR_PS_TEST_DIRECTORY_SERVER

    $credentialVariable = Get-Variable -Name SlmgrPsIntegrationCredential -Scope Global -ErrorAction SilentlyContinue
    $script:Credential = if ($null -eq $credentialVariable) { $null } else { $credentialVariable.Value }

    $directoryCredentialVariable = Get-Variable -Name SlmgrPsIntegrationDirectoryCredential -Scope Global -ErrorAction SilentlyContinue
    $script:DirectoryCredential = if ($null -eq $directoryCredentialVariable) { $null } else { $directoryCredentialVariable.Value }
}

Describe 'Integration matrix - read-only paths' -Tag 'Integration', 'ReadOnly' {
    It 'queries local Windows licensing state through the local CIM path' {
        $result = @(Get-WindowsActivation -Computer localhost -ErrorAction Stop)

        $result.Count | Should -BeGreaterThan 0
    }

    It 'queries the local token issuance-license provider without requiring installed token licenses' {
        { Get-WindowsTokenActivationLicense -Computer localhost -ErrorAction Stop | Out-Null } |
            Should -Not -Throw
    }

    It 'queries a remote computer through WinRM using the current identity' -Skip:(-not $hasRemoteComputer -or $hasCredential) {
        $result = @(Get-WindowsActivation -Computer $script:RemoteComputer -ErrorAction Stop)

        $result.Count | Should -BeGreaterThan 0
    }

    It 'queries a remote computer through WinRM using an explicit PSCredential' -Skip:(-not $hasRemoteComputer -or -not $hasCredential) {
        $result = @(Get-WindowsActivation `
                -Computer $script:RemoteComputer `
                -Credentials $script:Credential `
                -ErrorAction Stop)

        $result.Count | Should -BeGreaterThan 0
    }

    It 'reads real KMS host state when a KMS host target is supplied' -Skip:(-not $hasKmsHost) {
        $parameters = @{
            Computer = $script:KmsHost
            ErrorAction = 'Stop'
        }
        if ($null -ne $script:Credential) { $parameters['Credentials'] = $script:Credential }

        $result = Get-WindowsKmsHost @parameters

        $result.IsKmsHost | Should -BeTrue
        $result.ActivationInterval | Should -BeGreaterThan 0
        $result.RenewalInterval | Should -BeGreaterThan 0
    }

    It 'enumerates Active Directory activation objects when a directory server is supplied' -Skip:(-not $hasDirectoryServer) {
        $parameters = @{
            DirectoryServer = $script:DirectoryServer
            ErrorAction = 'Stop'
        }
        if ($null -ne $script:DirectoryCredential)
        {
            $parameters['DirectoryCredential'] = $script:DirectoryCredential
        }

        { Get-WindowsADActivationObject @parameters | Out-Null } | Should -Not -Throw
    }
}

Describe 'Integration matrix - destructive paths' -Tag 'Integration', 'Destructive' {
    It 'verifies a real KMS host mutation by writing its current activation interval' -Skip:(-not $hasKmsHost -or -not $allowMutation) {
        $readParameters = @{
            Computer = $script:KmsHost
            ErrorAction = 'Stop'
        }
        if ($null -ne $script:Credential) { $readParameters['Credentials'] = $script:Credential }

        $status = Get-WindowsKmsHost @readParameters
        $currentInterval = [int]$status.ActivationInterval
        $currentInterval | Should -BeGreaterThan 14
        $currentInterval | Should -BeLessThan 43201

        $writeParameters = @{
            Computer = $script:KmsHost
            ActivationInterval = $currentInterval
            Confirm = $false
            ErrorAction = 'Stop'
        }
        if ($null -ne $script:Credential) { $writeParameters['Credentials'] = $script:Credential }

        $result = @(Set-WindowsKmsHost @writeParameters)

        $result.Count | Should -Be 1
        $result[0].Success | Should -BeTrue
        $result[0].VerificationState | Should -Be 'Verified'
    }
}
