BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Get-WindowsLicensingProduct.ps1
    $script:MockCimSession = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
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
            $result = Get-WindowsLicensingProduct -CimSession $script:MockCimSession
            $result.Name | Should -Be 'Windows 11 Pro'
        }

        It 'uses the mutation filters by default' {
            Get-WindowsLicensingProduct -CimSession $script:MockCimSession
            Should -Invoke Get-CimInstance -ParameterFilter {
                $Query -match "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" -and
                $Query -match 'PartialProductKey IS NOT NULL' -and
                $Query -match 'LicenseIsAddon = FALSE' -and
                $ErrorAction -eq 'Stop'
            } -Times 1
        }
    }

    Context 'No matching products' {
        BeforeEach {
            Mock Get-CimInstance { @() }
        }

        It 'Throws with descriptive message' {
            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession } |
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
            $result = Get-WindowsLicensingProduct -CimSession $script:MockCimSession
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
            $result = Get-WindowsLicensingProduct -CimSession $script:MockCimSession
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
            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession } |
                Should -Throw -ExpectedMessage '*Multiple Windows licensing products*'
        }

        It 'Includes product names in the error' {
            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession } |
                Should -Throw -ExpectedMessage '*Windows 10 Pro*'
        }

        It 'Includes activation IDs in the error' {
            Mock Get-CimInstance {
                @(
                    [PSCustomObject]@{ Name = 'Windows 10 Pro'; ID = '11111111-1111-1111-1111-111111111111'; LicenseStatus = 5 }
                    [PSCustomObject]@{ Name = 'Windows 11 Pro'; ID = '22222222-2222-2222-2222-222222222222'; LicenseStatus = 5 }
                )
            }

            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession } |
                Should -Throw -ExpectedMessage '*11111111-1111-1111-1111-111111111111*'
        }
    }

    Context 'Activation ID selection' {
        BeforeEach {
            Mock Get-CimInstance {
                [PSCustomObject]@{
                    Name          = 'Non-Windows SPP product'
                    ID            = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    ApplicationID = '99999999-9999-9999-9999-999999999999'
                }
            }
        }

        It 'queries the exact product ID without a Windows application filter' {
            $result = Get-WindowsLicensingProduct -CimSession $script:MockCimSession `
                -ActivationId 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'

            $result.Name | Should -Be 'Non-Windows SPP product'
            Should -Invoke Get-CimInstance -ParameterFilter {
                $Query -match "ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'" -and
                $Query -notmatch 'ApplicationID ='
            } -Times 1
        }

        It 'adds the installed-key constraint when required' {
            Get-WindowsLicensingProduct -CimSession $script:MockCimSession `
                -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -RequireProductKey

            Should -Invoke Get-CimInstance -ParameterFilter {
                $Query -match 'PartialProductKey IS NOT NULL'
            } -Times 1
        }

        It 'throws when the activation ID is not found' {
            Mock Get-CimInstance { @() }

            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession `
                    -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' } |
                Should -Throw -ExpectedMessage '*activation ID aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee was not found*'
        }

        It 'rejects a malformed activation ID before querying CIM' {
            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession -ActivationId 'not-a-guid' } |
                Should -Throw
            Should -Invoke Get-CimInstance -Times 0
        }
    }

    Context 'All products selection' {
        It 'returns every product in deterministic order without a WHERE filter' {
            Mock Get-CimInstance {
                @(
                    [PSCustomObject]@{ Name = 'Product B'; ID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'; ApplicationID = '22222222-2222-2222-2222-222222222222' }
                    [PSCustomObject]@{ Name = 'Product A'; ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; ApplicationID = '11111111-1111-1111-1111-111111111111' }
                )
            }

            $result = @(Get-WindowsLicensingProduct -CimSession $script:MockCimSession -All)

            $result.Count | Should -Be 2
            $result[0].Name | Should -Be 'Product A'
            Should -Invoke Get-CimInstance -ParameterFilter { $Query -notmatch ' WHERE ' } -Times 1
        }

        It 'returns an empty collection without throwing' {
            Mock Get-CimInstance { @() }

            @(Get-WindowsLicensingProduct -CimSession $script:MockCimSession -All).Count |
                Should -Be 0
        }

        It 'cannot combine all products with an activation ID' {
            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession -All `
                    -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' } |
                Should -Throw
            Should -Invoke Get-CimInstance -Times 0
        }
    }

    Context 'Default read selection' {
        It 'returns the selected Windows product and keyed add-ons' {
            Mock Get-CimInstance {
                @(
                    [PSCustomObject]@{ Name = 'Windows 11 Pro'; ID = '11111111-1111-1111-1111-111111111111'; LicenseStatus = 1; LicenseIsAddon = $false }
                    [PSCustomObject]@{ Name = 'Windows Add-on'; ID = '22222222-2222-2222-2222-222222222222'; LicenseStatus = 1; LicenseIsAddon = $true }
                )
            }

            $result = @(Get-WindowsLicensingProduct -CimSession $script:MockCimSession -ForRead)

            $result.Count | Should -Be 2
            $result.Name | Should -Contain 'Windows 11 Pro'
            $result.Name | Should -Contain 'Windows Add-on'
        }
    }

    Context 'Installed key selection' {
        It 'selects the Windows base product by partial product key' {
            Mock Get-CimInstance {
                [PSCustomObject]@{
                    Name              = 'Windows 11 Pro'
                    ID                = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                    PartialProductKey = 'EEEEE'
                }
            }

            $result = Get-WindowsLicensingProduct -CimSession $script:MockCimSession `
                -PartialProductKey 'eeeee'

            $result.Name | Should -Be 'Windows 11 Pro'
            Should -Invoke Get-CimInstance -Times 1 -ParameterFilter {
                $Query -match "PartialProductKey = 'EEEEE'" -and
                $Query -match "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" -and
                $Query -match 'LicenseIsAddon = FALSE'
            }
        }

        It 'throws when the installed key cannot be resolved' {
            Mock Get-CimInstance { @() }

            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession `
                    -PartialProductKey 'EEEEE' } |
                Should -Throw -ExpectedMessage '*was not found after installation*'
        }

        It 'throws when the partial key is ambiguous' {
            Mock Get-CimInstance {
                @(
                    [PSCustomObject]@{ Name = 'Product A'; PartialProductKey = 'EEEEE' }
                    [PSCustomObject]@{ Name = 'Product B'; PartialProductKey = 'EEEEE' }
                )
            }

            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession `
                    -PartialProductKey 'EEEEE' } |
                Should -Throw -ExpectedMessage '*cannot continue safely*'
        }

        It 'rejects an invalid partial key before querying CIM' {
            { Get-WindowsLicensingProduct -CimSession $script:MockCimSession `
                    -PartialProductKey 'BAD' } | Should -Throw

            Should -Invoke Get-CimInstance -Times 0
        }
    }
}
