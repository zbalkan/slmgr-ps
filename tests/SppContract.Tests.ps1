Describe 'Windows SPP CIM contract' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeAll {
        . $PSScriptRoot/../src/Private/Get-SppContract.ps1
        $script:Contract = Get-SppContract
        $script:ServiceClass = Get-CimClass -Namespace root/cimv2 -ClassName SoftwareLicensingService
        $script:ProductClass = Get-CimClass -Namespace root/cimv2 -ClassName SoftwareLicensingProduct
        $script:TokenLicenseClass = Get-CimClass -Namespace root/cimv2 -ClassName SoftwareLicensingTokenActivationLicense
    }

    It 'exposes the product properties required for targeting' {
        foreach ($property in $script:Contract.ProductProperties)
        {
            $script:ProductClass.CimClassProperties.Name | Should -Contain $property
        }
    }

    It 'exposes the service properties required for KMS and token reporting' {
        foreach ($property in $script:Contract.ServiceProperties)
        {
            $script:ServiceClass.CimClassProperties.Name | Should -Contain $property
        }
    }

    It 'exposes the documented token activation license properties' {
        foreach ($property in $script:Contract.TokenActivationLicenseProperties)
        {
            $script:TokenLicenseClass.CimClassProperties.Name | Should -Contain $property
        }
    }

    It 'exposes every method on each allowed licensing class' {
        foreach ($method in $script:Contract.Methods.Keys)
        {
            foreach ($className in $script:Contract.Methods[$method].Classes)
            {
                $class = switch ($className)
                {
                    'SoftwareLicensingService' { $script:ServiceClass }
                    'SoftwareLicensingTokenActivationLicense' { $script:TokenLicenseClass }
                    default { $script:ProductClass }
                }
                $class.CimClassMethods.Name | Should -Contain $method
            }
        }
    }

    It 'uses the documented provider input argument names' {
        foreach ($method in $script:Contract.Methods.Keys)
        {
            $expectedArguments = @($script:Contract.Methods[$method].Arguments)
            if ($expectedArguments.Count -eq 0) { continue }

            $className = @($script:Contract.Methods[$method].Classes)[0]
            $class = switch ($className)
            {
                'SoftwareLicensingService' { $script:ServiceClass }
                'SoftwareLicensingTokenActivationLicense' { $script:TokenLicenseClass }
                default { $script:ProductClass }
            }
            $declaration = @($class.CimClassMethods | Where-Object Name -eq $method)[0]
            $actualArguments = @($declaration.Parameters | Where-Object {
                    $inQualifier = $_.Qualifiers['In']
                    $null -ne $inQualifier -and $inQualifier.Value
                } | ForEach-Object Name)
            $actualArguments.Count | Should -Be $expectedArguments.Count
            foreach ($argument in $expectedArguments)
            {
                $actualArguments | Should -Contain $argument
            }
        }
    }

    It 'exposes InstallationID as the AD offline activation output' {
        $method = @($script:ServiceClass.CimClassMethods | Where-Object Name -eq 'GenerateActiveDirectoryOfflineActivationId')[0]
        $output = @($method.Parameters | Where-Object Name -eq 'InstallationID')[0]
        $output | Should -Not -BeNullOrEmpty
        $output.Qualifiers['Out'].Value | Should -BeTrue
    }
}
