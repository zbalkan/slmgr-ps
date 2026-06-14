BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Get-WindowsLicensingProduct.ps1
    . $PSScriptRoot/../src/Private/Get-ExpiryInformation.ps1
}

Describe 'Get-ExpiryInformation' {

    It 'Reports permanent activation when Licensed with no grace remaining' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{
                Name                = 'Windows 11 Pro'
                LicenseStatus       = 1
                GracePeriodRemaining = 0
                Description         = 'Volume:GVLK'
            }
        }
        $result = Get-ExpiryInformation -CimSession $null
        $result.ExpirationInfo | Should -Be 'The machine is permanently activated.'
    }

    It 'Reports permanent activation when Licensed with null grace' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{
                Name                = 'Windows 11 Pro'
                LicenseStatus       = 1
                GracePeriodRemaining = $null
                Description         = 'Volume:GVLK'
            }
        }
        $result = Get-ExpiryInformation -CimSession $null
        $result.ExpirationInfo | Should -Be 'The machine is permanently activated.'
    }

    It 'Reports timebased expiry for TIMEBASED_ description' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{
                Name                = 'Windows 11 Pro'
                LicenseStatus       = 1
                GracePeriodRemaining = 43200
                Description         = 'Volume:GVLK:TIMEBASED_'
            }
        }
        $result = Get-ExpiryInformation -CimSession $null
        $result.ExpirationInfo | Should -Match 'Timebased activation will expire'
    }

    It 'Reports VM activation expiry for VIRTUAL_MACHINE_ACTIVATION description' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{
                Name                = 'Windows 11 Pro'
                LicenseStatus       = 1
                GracePeriodRemaining = 43200
                Description         = 'Volume:GVLK:VIRTUAL_MACHINE_ACTIVATION'
            }
        }
        $result = Get-ExpiryInformation -CimSession $null
        $result.ExpirationInfo | Should -Match 'Automatic VM activation will expire'
    }

    It 'Reports OOBGrace end date when status is 2' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{
                Name                = 'Windows 11 Pro'
                LicenseStatus       = 2
                GracePeriodRemaining = 43200
                Description         = ''
            }
        }
        $result = Get-ExpiryInformation -CimSession $null
        $result.ExpirationInfo | Should -Match 'Initial grace period ends'
    }

    It 'Uses PascalCase property names' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{
                Name                = 'Windows 11 Pro'
                LicenseStatus       = 1
                GracePeriodRemaining = 0
                Description         = ''
            }
        }
        $result = Get-ExpiryInformation -CimSession $null
        $result.PSObject.Properties.Name | Should -Contain 'LicenseStatus'
        $result.PSObject.Properties.Name | Should -Contain 'ExpirationInfo'
        $result.PSObject.Properties.Name | Should -Not -Contain 'License Status'
        $result.PSObject.Properties.Name | Should -Not -Contain 'Expiration Information'
    }
}
