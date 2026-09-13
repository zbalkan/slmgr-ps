BeforeAll {
    . $PSScriptRoot/../src/Private/Get-SppContract.ps1
}

Describe 'Token activation license provider contract' {
    It 'defines the documented token activation license properties' {
        $contract = Get-SppContract

        $contract.TokenActivationLicenseProperties | Should -Contain 'ID'
        $contract.TokenActivationLicenseProperties | Should -Contain 'ILID'
        $contract.TokenActivationLicenseProperties | Should -Contain 'ILVID'
        $contract.TokenActivationLicenseProperties | Should -Contain 'AuthorizationStatus'
        $contract.TokenActivationLicenseProperties | Should -Contain 'ExpirationDate'
        $contract.TokenActivationLicenseProperties | Should -Contain 'Description'
        $contract.TokenActivationLicenseProperties | Should -Contain 'AdditionalInfo'
    }

    It 'owns Uninstall on SoftwareLicensingTokenActivationLicense without arguments' {
        $contract = Get-SppContract

        $contract.Methods.Uninstall.Classes | Should -Be @('SoftwareLicensingTokenActivationLicense')
        $contract.Methods.Uninstall.Arguments.Count | Should -Be 0
    }

    It 'defines token activation reporting properties on product and service contracts' {
        $contract = Get-SppContract
        $properties = @(
            'TokenActivationILID'
            'TokenActivationILVID'
            'TokenActivationGrantNumber'
            'TokenActivationCertificateThumbprint'
            'TokenActivationAdditionalInfo'
        )

        foreach ($property in $properties)
        {
            $contract.ProductProperties | Should -Contain $property
            $contract.ServiceProperties | Should -Contain $property
        }
    }
}
