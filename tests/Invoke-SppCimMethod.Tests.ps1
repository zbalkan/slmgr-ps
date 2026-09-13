BeforeAll {
    . $PSScriptRoot/../src/Private/Get-SppContract.ps1
    . $PSScriptRoot/../src/Private/Invoke-SppCimMethod.ps1

    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
    $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly
}

Describe 'Invoke-SppCimMethod' {
    BeforeEach {
        Mock Invoke-CimMethod { [PSCustomObject]@{ ReturnValue = 0 } }
    }

    It 'accepts a service method on SoftwareLicensingService' {
        $script:Service | Invoke-SppCimMethod -MethodName ClearProductKeyFromRegistry
        Should -Invoke Invoke-CimMethod -ParameterFilter {
            $MethodName -eq 'ClearProductKeyFromRegistry'
        } -Times 1
    }

    It 'rejects a service method on SoftwareLicensingProduct' {
        { $script:Product | Invoke-SppCimMethod -MethodName ClearProductKeyFromRegistry } |
            Should -Throw -ExpectedMessage '*requires SoftwareLicensingService*'
        Should -Invoke Invoke-CimMethod -Times 0
    }

    It 'accepts a product method on SoftwareLicensingProduct' {
        $script:Product | Invoke-SppCimMethod -MethodName Activate
        Should -Invoke Invoke-CimMethod -ParameterFilter { $MethodName -eq 'Activate' } -Times 1
    }

    It 'rejects a product method on SoftwareLicensingService' {
        { $script:Service | Invoke-SppCimMethod -MethodName Activate } |
            Should -Throw -ExpectedMessage '*requires SoftwareLicensingProduct*'
        Should -Invoke Invoke-CimMethod -Times 0
    }

    It 'accepts a KMS client method on either licensing class' {
        $script:Service | Invoke-SppCimMethod -MethodName ClearKeyManagementServiceMachine
        $script:Product | Invoke-SppCimMethod -MethodName ClearKeyManagementServiceMachine

        Should -Invoke Invoke-CimMethod -ParameterFilter {
            $MethodName -eq 'ClearKeyManagementServiceMachine'
        } -Times 2
    }

    It 'throws when the provider returns a non-zero value' {
        Mock Invoke-CimMethod { [PSCustomObject]@{ ReturnValue = 5 } }
        { $script:Product | Invoke-SppCimMethod -MethodName Activate } |
            Should -Throw -ExpectedMessage '*return value: 5*'
    }

    It 'forwards the product key with the provider argument name' {
        $script:Service | Invoke-SppCimMethod -MethodName InstallProductKey `
            -Arguments @{ ProductKey = 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX' }

        Should -Invoke Invoke-CimMethod -ParameterFilter {
            $MethodName -eq 'InstallProductKey' -and
            $Arguments.ProductKey -eq 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'
        } -Times 1
    }

    It 'forwards license content to the licensing service' {
        $script:Service | Invoke-SppCimMethod -MethodName InstallLicense `
            -Arguments @{ License = '<license />' }

        Should -Invoke Invoke-CimMethod -ParameterFilter {
            $MethodName -eq 'InstallLicense' -and
            $Arguments.License -eq '<license />'
        } -Times 1
    }

    It 'routes application rearm to the licensing service' {
        $applicationId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $script:Service | Invoke-SppCimMethod -MethodName ReArmApp `
            -Arguments @{ ApplicationId = $applicationId }

        Should -Invoke Invoke-CimMethod -ParameterFilter {
            $MethodName -eq 'ReArmApp' -and
            $Arguments.ApplicationId -eq $applicationId
        } -Times 1
    }

    It 'routes SKU rearm to a licensing product' {
        $script:Product | Invoke-SppCimMethod -MethodName ReArmSku

        Should -Invoke Invoke-CimMethod -ParameterFilter {
            $MethodName -eq 'ReArmSku'
        } -Times 1
    }

    It 'forwards both offline activation arguments' {
        $script:Product | Invoke-SppCimMethod -MethodName DepositOfflineConfirmationId -Arguments @{
            InstallationId = '123456789'
            ConfirmationId = '987654321'
        }

        Should -Invoke Invoke-CimMethod -ParameterFilter {
            $MethodName -eq 'DepositOfflineConfirmationId' -and
            $Arguments.InstallationId -eq '123456789' -and
            $Arguments.ConfirmationId -eq '987654321'
        } -Times 1
    }

    It 'rejects a missing provider argument' {
        { $script:Service | Invoke-SppCimMethod -MethodName InstallProductKey } |
            Should -Throw -ExpectedMessage '*requires argument(s): ProductKey*'
        Should -Invoke Invoke-CimMethod -Times 0
    }

    It 'rejects an unexpected provider argument' {
        { $script:Product | Invoke-SppCimMethod -MethodName Activate -Arguments @{ Force = $true } } |
            Should -Throw -ExpectedMessage '*does not accept argument(s): Force*'
        Should -Invoke Invoke-CimMethod -Times 0
    }

    It 'rejects a method outside the supported contract' {
        { $script:Service | Invoke-SppCimMethod -MethodName UnknownMethod } |
            Should -Throw -ExpectedMessage '*Unsupported SPP method*'
        Should -Invoke Invoke-CimMethod -Times 0
    }
}
