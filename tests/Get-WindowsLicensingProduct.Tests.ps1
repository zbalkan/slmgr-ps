BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Get-WindowsLicensingProduct.ps1
}

Describe 'Get-WindowsLicensingProduct' {

    Context 'Single matching product' {
        BeforeEach {
            Mock Get-CimInstance {
                [PSCustomObject]@{
                    Name              = 'Windows 11 Pro'
                    LicenseStatus     = 1
                    PartialProductKey = 'W7R9X'
                }
            }
        }

        It 'Returns the single product' {
            $result = Get-WindowsLicensingProduct -CimSession $null
            $result.Name | Should -Be 'Windows 11 Pro'
        }
    }

    Context 'No matching products' {
        BeforeEach {
            Mock Get-CimInstance { @() }
        }

        It 'Throws with descriptive message' {
            { Get-WindowsLicensingProduct -CimSession $null } |
                Should -Throw -ExpectedMessage '*No Windows licensing product*'
        }
    }

    Context 'Multiple products - one Licensed' {
        BeforeEach {
            Mock Get-CimInstance {
                @(
                    [PSCustomObject]@{ Name = 'Windows 10 Pro'; LicenseStatus = 5; PartialProductKey = 'XXXXX' }
                    [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 1; PartialProductKey = 'YYYYY' }
                )
            }
        }

        It 'Returns the Licensed product' {
            $result = Get-WindowsLicensingProduct -CimSession $null
            $result.Name | Should -Be 'Windows 11 Pro'
        }
    }

    Context 'Multiple products - one non-zero, none Licensed' {
        BeforeEach {
            Mock Get-CimInstance {
                @(
                    [PSCustomObject]@{ Name = 'Windows 10 Pro'; LicenseStatus = 0; PartialProductKey = 'XXXXX' }
                    [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 5; PartialProductKey = 'YYYYY' }
                )
            }
        }

        It 'Returns the active product' {
            $result = Get-WindowsLicensingProduct -CimSession $null
            $result.Name | Should -Be 'Windows 11 Pro'
        }
    }

    Context 'Multiple products - ambiguous' {
        BeforeEach {
            Mock Get-CimInstance {
                @(
                    [PSCustomObject]@{ Name = 'Windows 10 Pro'; LicenseStatus = 5; PartialProductKey = 'XXXXX' }
                    [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 5; PartialProductKey = 'YYYYY' }
                )
            }
        }

        It 'Throws with candidate list' {
            { Get-WindowsLicensingProduct -CimSession $null } |
                Should -Throw -ExpectedMessage '*Multiple Windows licensing products*'
        }

        It 'Includes product names in the error' {
            { Get-WindowsLicensingProduct -CimSession $null } |
                Should -Throw -ExpectedMessage '*Windows 10 Pro*'
        }
    }
}
