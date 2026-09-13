BeforeAll {
    $script:Contract = Import-PowerShellDataFile $PSScriptRoot/PublicContract.psd1
    . $PSScriptRoot/../src/Private/New-LicensingOperationResult.ps1
}

Describe 'New-LicensingOperationResult' {
    It 'creates the stable licensing operation result shape' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $result = New-LicensingOperationResult `
            -ComputerName 'WS01' `
            -Operation 'Activate' `
            -Success $true `
            -ActivationId $activationId `
            -ProductName 'Windows' `
            -VerificationState Verified

        $resultContract = $script:Contract.ResultContracts.LicensingOperationResult
        $result.PSObject.TypeNames[0] | Should -Be $resultContract.TypeName
        $result.PSObject.Properties.Name | Should -Be $resultContract.Properties
        $result.ComputerName | Should -Be 'WS01'
        $result.Success | Should -BeTrue
        $result.Operation | Should -Be 'Activate'
        $result.ActivationId | Should -Be $activationId
        $result.ProductName | Should -Be 'Windows'
        $result.RestartRequired | Should -BeFalse
        $result.ErrorCode | Should -BeNullOrEmpty
        $result.ErrorMessage | Should -BeNullOrEmpty
        $result.VerificationState | Should -Be 'Verified'
    }

    It 'represents failed and unverifiable outcomes without inventing values' {
        $result = New-LicensingOperationResult `
            -ComputerName 'localhost' `
            -Operation 'InstallLicense' `
            -Success $false `
            -RestartRequired $true `
            -ErrorCode '0xC004F050' `
            -ErrorMessage 'Provider rejected the operation.' `
            -VerificationState Failed

        $result.ActivationId | Should -BeNullOrEmpty
        $result.ProductName | Should -BeNullOrEmpty
        $result.RestartRequired | Should -BeTrue
        $result.ErrorCode | Should -Be '0xC004F050'
        $result.ErrorMessage | Should -Be 'Provider rejected the operation.'
        $result.VerificationState | Should -Be 'Failed'
    }

    It 'accepts every verification state declared by the public contract' {
        foreach ($verificationState in $script:Contract.ResultContracts.LicensingOperationResult.VerificationStates)
        {
            $success = $verificationState -ne 'Failed'
            { New-LicensingOperationResult -ComputerName localhost -Operation Test `
                    -Success $success -VerificationState $verificationState } | Should -Not -Throw
        }
    }

    It 'rejects unknown verification states' {
        { New-LicensingOperationResult -ComputerName localhost -Operation Test `
                -Success $true -VerificationState Unknown } | Should -Throw
    }
}
