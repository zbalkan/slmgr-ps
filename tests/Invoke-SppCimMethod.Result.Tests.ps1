BeforeAll {
    . $PSScriptRoot/../src/Private/Get-SppContract.ps1
    . $PSScriptRoot/../src/Private/Invoke-SppCimMethod.ps1

    $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly
}

Describe 'Invoke-SppCimMethod result contract' {
    It 'returns the provider result only when PassThru is requested' {
        Mock Invoke-CimMethod { [PSCustomObject]@{ ReturnValue = 0; ProviderValue = 'ok' } }

        $defaultResult = @($script:Product | Invoke-SppCimMethod -MethodName Activate)
        $passThruResult = $script:Product | Invoke-SppCimMethod -MethodName Activate -PassThru

        $defaultResult.Count | Should -Be 0
        $passThruResult.ReturnValue | Should -Be 0
        $passThruResult.ProviderValue | Should -Be 'ok'
    }

    It 'preserves provider failure identity and hexadecimal error code' {
        Mock Invoke-CimMethod { [PSCustomObject]@{ ReturnValue = [uint32]3221549136 } }

        $caught = $null
        try
        {
            $script:Product | Invoke-SppCimMethod -MethodName Activate
        }
        catch
        {
            $caught = $_
        }

        $caught | Should -Not -BeNullOrEmpty
        $caught.FullyQualifiedErrorId | Should -Match '^SppProviderMethodFailed'
        $caught.Exception.Data['ProviderReturnValue'] | Should -Be ([uint32]3221549136)
        $caught.Exception.Data['ErrorCode'] | Should -Be '0xC004F050'
        $caught.Exception.Data['MethodName'] | Should -Be 'Activate'
        $caught.TargetObject.MethodName | Should -Be 'Activate'
        $caught.TargetObject.ClassName | Should -Be 'SoftwareLicensingProduct'
        $caught.TargetObject.ErrorCode | Should -Be '0xC004F050'
    }
}
