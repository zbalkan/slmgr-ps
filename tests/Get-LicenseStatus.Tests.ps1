BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Get-WindowsLicensingProduct.ps1
    . $PSScriptRoot/../src/Private/Get-LicenseStatus.ps1
}

Describe 'Get-LicenseStatus' {

    It 'Returns Activated=true when LicenseStatus is Licensed (1)' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 1 }
        }
        $result = Get-LicenseStatus -CimSession $null
        $result.Activated | Should -BeTrue
        $result.LicenseStatus | Should -Be ([LicenseStatusCode]::Licensed)
    }

    It 'Returns Activated=false when LicenseStatus is OOBGrace (2)' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 2 }
        }
        $result = Get-LicenseStatus -CimSession $null
        $result.Activated | Should -BeFalse
        $result.LicenseStatus | Should -Be ([LicenseStatusCode]::OOBGrace)
    }

    It 'Returns Activated=false when LicenseStatus is Notification (5)' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 5 }
        }
        $result = Get-LicenseStatus -CimSession $null
        $result.Activated | Should -BeFalse
        $result.LicenseStatus | Should -Be ([LicenseStatusCode]::Notification)
    }

    It 'Exposes LicenseStatus property (not space-separated)' {
        Mock Get-WindowsLicensingProduct {
            [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 1 }
        }
        $result = Get-LicenseStatus -CimSession $null
        $result.PSObject.Properties.Name | Should -Contain 'LicenseStatus'
        $result.PSObject.Properties.Name | Should -Not -Contain 'License Status'
    }
}
