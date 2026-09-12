Describe 'Windows SPP CIM contract' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeAll {
        . $PSScriptRoot/../src/Private/Get-SppContract.ps1
        $script:Contract = Get-SppContract
        $script:ServiceClass = Get-CimClass -Namespace root/cimv2 -ClassName SoftwareLicensingService
        $script:ProductClass = Get-CimClass -Namespace root/cimv2 -ClassName SoftwareLicensingProduct
    }

    It 'exposes the product properties required for targeting' {
        foreach ($property in $script:Contract.ProductProperties)
        {
            $script:ProductClass.CimClassProperties.Name | Should -Contain $property
        }
    }

    It 'exposes every method on each allowed licensing class' {
        foreach ($method in $script:Contract.Methods.Keys)
        {
            foreach ($className in $script:Contract.Methods[$method].Classes)
            {
                $class = if ($className -eq 'SoftwareLicensingService')
                {
                    $script:ServiceClass
                }
                else
                {
                    $script:ProductClass
                }
                $class.CimClassMethods.Name | Should -Contain $method
            }
        }
    }

    It 'uses the documented provider argument names' {
        foreach ($method in $script:Contract.Methods.Keys)
        {
            $expectedArguments = @($script:Contract.Methods[$method].Arguments)
            if ($expectedArguments.Count -eq 0) { continue }

            $className = @($script:Contract.Methods[$method].Classes)[0]
            $class = if ($className -eq 'SoftwareLicensingService')
            {
                $script:ServiceClass
            }
            else
            {
                $script:ProductClass
            }
            $declaration = @($class.CimClassMethods | Where-Object Name -eq $method)[0]
            $actualArguments = @($declaration.Parameters.Name)
            $actualArguments.Count | Should -Be $expectedArguments.Count
            foreach ($argument in $expectedArguments)
            {
                $actualArguments | Should -Contain $argument
            }
        }
    }
}
