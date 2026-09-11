BeforeAll {
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
        Should -Invoke Invoke-CimMethod -Times 1
    }

    It 'rejects a service method on SoftwareLicensingProduct' {
        { $script:Product | Invoke-SppCimMethod -MethodName ClearProductKeyFromRegistry } |
            Should -Throw -ExpectedMessage '*requires SoftwareLicensingService*'
        Should -Invoke Invoke-CimMethod -Times 0
    }

    It 'accepts a product method on SoftwareLicensingProduct' {
        $script:Product | Invoke-SppCimMethod -MethodName Activate
        Should -Invoke Invoke-CimMethod -Times 1
    }

    It 'rejects a product method on SoftwareLicensingService' {
        { $script:Service | Invoke-SppCimMethod -MethodName Activate } |
            Should -Throw -ExpectedMessage '*requires SoftwareLicensingProduct*'
        Should -Invoke Invoke-CimMethod -Times 0
    }

    It 'throws when the provider returns a non-zero value' {
        Mock Invoke-CimMethod { [PSCustomObject]@{ ReturnValue = 5 } }
        { $script:Product | Invoke-SppCimMethod -MethodName Activate } |
            Should -Throw -ExpectedMessage '*return value: 5*'
    }
}
