Describe 'Windows SPP CIM contract' -Skip:(-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    BeforeAll {
        $script:ServiceClass = Get-CimClass -Namespace root/cimv2 -ClassName SoftwareLicensingService
        $script:ProductClass = Get-CimClass -Namespace root/cimv2 -ClassName SoftwareLicensingProduct
    }

    It 'exposes service-scoped methods on SoftwareLicensingService' {
        $expectedMethods = @(
            'ClearKeyManagementServiceMachine',
            'ClearKeyManagementServicePort',
            'ClearProductKeyFromRegistry',
            'DisableKeyManagementServiceHostCaching',
            'InstallProductKey',
            'ReArmWindows',
            'RefreshLicenseStatus',
            'SetKeyManagementServiceMachine',
            'SetKeyManagementServicePort'
        )

        foreach ($method in $expectedMethods)
        {
            $script:ServiceClass.CimClassMethods.Name | Should -Contain $method
        }
    }

    It 'exposes product-scoped methods on SoftwareLicensingProduct' {
        $expectedMethods = @('Activate', 'DepositOfflineConfirmationId', 'UninstallProductKey')
        foreach ($method in $expectedMethods)
        {
            $script:ProductClass.CimClassMethods.Name | Should -Contain $method
        }
    }

    It 'does not expose ClearProductKeyFromRegistry on SoftwareLicensingProduct' {
        $script:ProductClass.CimClassMethods.Name | Should -Not -Contain 'ClearProductKeyFromRegistry'
    }
}
