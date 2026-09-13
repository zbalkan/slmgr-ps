BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Get-ExtendedLicenseInformation.ps1
    function Get-WindowsLicensingProduct { param($CimSession) }
}

Describe 'Activation type reporting' {
    It 'reports configured and last-used activation type values' {
        $product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            LicenseStatus           = [uint32]1
            VLActivationType        = [uint32]2
            VLActivationTypeEnabled = [uint32]2
        }

        $result = Get-ExtendedLicenseInformation -Product $product

        $result.LastVolumeActivationTypeCode | Should -Be 2
        $result.ActivationTypePolicyCode | Should -Be 2
        $result.ActivationTypePolicy | Should -Be 'Kms'
    }

    It 'maps policy value 0 to Any' {
        $product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            LicenseStatus           = [uint32]0
            VLActivationTypeEnabled = [uint32]0
        }

        (Get-ExtendedLicenseInformation -Product $product).ActivationTypePolicy |
            Should -Be 'Any'
    }

    It 'maps policy value 1 to ActiveDirectory' {
        $product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            LicenseStatus           = [uint32]0
            VLActivationTypeEnabled = [uint32]1
        }

        (Get-ExtendedLicenseInformation -Product $product).ActivationTypePolicy |
            Should -Be 'ActiveDirectory'
    }

    It 'maps policy value 3 to Token' {
        $product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            LicenseStatus           = [uint32]0
            VLActivationTypeEnabled = [uint32]3
        }

        (Get-ExtendedLicenseInformation -Product $product).ActivationTypePolicy |
            Should -Be 'Token'
    }
}
