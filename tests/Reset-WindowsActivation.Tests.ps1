BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Get-Session.ps1
    . $PSScriptRoot/../src/Private/Get-WindowsLicensingProduct.ps1

    # Define a stub without the [CimInstance] type constraint so PSCustomObject
    # mocks can flow through the pipeline without a ParameterBindingException.
    function Invoke-SppCimMethod {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, ValueFromPipeline)]$InputObject,
            [Parameter(Mandatory)][string]$MethodName,
            [hashtable]$Arguments
        )
    }

    . $PSScriptRoot/../src/Public/Reset-WindowsActivation.ps1
    $script:MockCimSession = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
}

Describe 'Reset-WindowsActivation' {

    Context 'No switches specified' {
        It 'Throws requiring at least one operation' {
            { Reset-WindowsActivation -Confirm:$false } |
                Should -Throw -ExpectedMessage '*At least one reset operation must be specified*'
        }
    }

    Context 'UninstallProductKey' {
        BeforeEach {
            Mock Get-Session { $script:MockCimSession }
            Mock Remove-CimSession {}
            Mock Get-WindowsLicensingProduct {
                [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 1 }
            }
            Mock Invoke-SppCimMethod {}
        }

        It 'Calls UninstallProductKey on the product' {
            Reset-WindowsActivation -UninstallProductKey -Confirm:$false
            Should -Invoke Invoke-SppCimMethod -ParameterFilter { $MethodName -eq 'UninstallProductKey' } -Times 1
        }

        It 'Does not call ClearProductKeyFromRegistry' {
            Reset-WindowsActivation -UninstallProductKey -Confirm:$false
            Should -Invoke Invoke-SppCimMethod -ParameterFilter { $MethodName -eq 'ClearProductKeyFromRegistry' } -Times 0
        }

        It 'Does not call ClearKeyManagementServiceMachine' {
            Reset-WindowsActivation -UninstallProductKey -Confirm:$false
            Should -Invoke Invoke-SppCimMethod -ParameterFilter { $MethodName -eq 'ClearKeyManagementServiceMachine' } -Times 0
        }
    }

    Context 'ClearProductKeyFromRegistry' {
        BeforeEach {
            Mock Get-Session { $script:MockCimSession }
            Mock Remove-CimSession {}
            Mock Get-WindowsLicensingProduct {
                [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 1 }
            }
            Mock Invoke-SppCimMethod {}
        }

        It 'Calls ClearProductKeyFromRegistry on the product' {
            Reset-WindowsActivation -ClearProductKeyFromRegistry -Confirm:$false
            Should -Invoke Invoke-SppCimMethod -ParameterFilter { $MethodName -eq 'ClearProductKeyFromRegistry' } -Times 1
        }
    }

    Context 'ClearKMSSettings' {
        BeforeEach {
            Mock Get-Session { $script:MockCimSession }
            Mock Remove-CimSession {}
            Mock Get-WindowsLicensingProduct {}
            Mock Get-CimInstance {
                [PSCustomObject]@{ ClassName = 'SoftwareLicensingService' }
            }
            Mock Invoke-SppCimMethod {}
        }

        It 'Calls ClearKeyManagementServiceMachine on the service' {
            Reset-WindowsActivation -ClearKMSSettings -Confirm:$false
            Should -Invoke Invoke-SppCimMethod -ParameterFilter { $MethodName -eq 'ClearKeyManagementServiceMachine' } -Times 1
        }

        It 'Does not look up the product' {
            Reset-WindowsActivation -ClearKMSSettings -Confirm:$false
            Should -Invoke Get-WindowsLicensingProduct -Times 0
        }
    }

    Context 'Combined switches' {
        BeforeEach {
            Mock Get-Session { $script:MockCimSession }
            Mock Remove-CimSession {}
            Mock Get-WindowsLicensingProduct {
                [PSCustomObject]@{ Name = 'Windows 11 Pro'; LicenseStatus = 1 }
            }
            Mock Get-CimInstance {
                [PSCustomObject]@{ ClassName = 'SoftwareLicensingService' }
            }
            Mock Invoke-SppCimMethod {}
        }

        It 'Calls all three methods when all switches are specified' {
            Reset-WindowsActivation -UninstallProductKey -ClearProductKeyFromRegistry -ClearKMSSettings -Confirm:$false
            Should -Invoke Invoke-SppCimMethod -Times 3
        }
    }

    Context 'Session cleanup' {
        BeforeEach {
            Mock Get-Session { $script:MockCimSession }
            Mock Remove-CimSession {}
            Mock Get-WindowsLicensingProduct { throw 'Simulated failure' }
        }

        It 'Removes the CIM session even when an error occurs' {
            { Reset-WindowsActivation -UninstallProductKey -Confirm:$false } | Should -Throw
            Should -Invoke Remove-CimSession -Times 1
        }
    }
}
