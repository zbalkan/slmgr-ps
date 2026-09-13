BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Get-ExtendedLicenseInformation.ps1
    function Get-WindowsLicensingProduct { param($CimSession) }
}

Describe 'Get-ExtendedLicenseInformation KMS client state' {
    It 'reports configured, discovered, lookup-domain, and caching values' {
        $product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            Name                                      = 'Windows'
            LicenseStatus                             = 1
            KeyManagementServiceMachine               = 'kms01.example.test'
            KeyManagementServicePort                  = 2500
            DiscoveredKeyManagementServiceMachineName = 'kms02.example.test'
            DiscoveredKeyManagementServiceMachinePort = 1688
            KeyManagementServiceLookupDomain          = 'activation.example.test'
        }
        $service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly -Property @{
            KeyManagementServiceHostCaching = $false
        }

        $result = Get-ExtendedLicenseInformation -Product $product -Service $service

        $result.ConfiguredKmsHost | Should -Be 'kms01.example.test'
        $result.ConfiguredKmsPort | Should -Be 2500
        $result.DiscoveredKmsHost | Should -Be 'kms02.example.test'
        $result.DiscoveredKmsPort | Should -Be 1688
        $result.KmsLookupDomain | Should -Be 'activation.example.test'
        $result.KmsHostCaching | Should -Be 'Disabled'
    }

    It 'reports unset ports and unavailable caching state as null' {
        $product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            LicenseStatus                             = 0
            KeyManagementServicePort                  = 0
            DiscoveredKeyManagementServiceMachinePort = 0
        }
        $service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly

        $result = Get-ExtendedLicenseInformation -Product $product -Service $service

        $result.ConfiguredKmsPort | Should -BeNullOrEmpty
        $result.DiscoveredKmsPort | Should -BeNullOrEmpty
        $result.KmsHostCaching | Should -BeNullOrEmpty
    }
}
