BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Invoke-OfflineActivation.ps1

    function Get-LicenseStatus {}
    function Get-WindowsLicensingProduct {}
    function Get-OfflineInstallationId {}
    function Invoke-SppCimMethod {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, ValueFromPipeline)]$InputObject,
            [Parameter(Mandatory)][string]$MethodName,
            [hashtable]$Arguments
        )
    }

    $script:MockCimSession = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
    $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly
}

Describe 'Invoke-OfflineActivation' {
    BeforeEach {
        $script:StatusCall = 0
        Mock Get-LicenseStatus {
            $script:StatusCall++
            if ($script:StatusCall -eq 1)
            {
                [PSCustomObject]@{ LicenseStatus = [LicenseStatusCode]::Unlicensed; Activated = $false }
            }
            else
            {
                [PSCustomObject]@{ LicenseStatus = [LicenseStatusCode]::Licensed; Activated = $true }
            }
        }
        Mock Get-WindowsLicensingProduct { $script:Product }
        Mock Get-OfflineInstallationId { [PSCustomObject]@{ OfflineInstallationId = '123456789' } }
        Mock Invoke-SppCimMethod {}
    }

    It 'normalizes and deposits the confirmation ID' {
        Invoke-OfflineActivation -CimSession $script:MockCimSession -Service $script:Service `
            -ConfirmationId '123456-123456-123456-123456-123456-123456-123456-123456-123456'

        Should -Invoke Invoke-SppCimMethod -ParameterFilter {
            $MethodName -eq 'DepositOfflineConfirmationId' -and
            $Arguments.ConfirmationId -eq '123456123456123456123456123456123456123456123456123456'
        } -Times 1
    }

    It 'removes spaces from the confirmation ID' {
        Invoke-OfflineActivation -CimSession $script:MockCimSession -Service $script:Service `
            -ConfirmationId '123456 123456 123456 123456 123456 123456 123456 123456 123456'

        Should -Invoke Invoke-SppCimMethod -ParameterFilter {
            $MethodName -eq 'DepositOfflineConfirmationId' -and
            $Arguments.ConfirmationId -eq '123456123456123456123456123456123456123456123456123456'
        } -Times 1
    }

    It 'does not submit an offline activation when already activated' {
        Mock Get-LicenseStatus {
            [PSCustomObject]@{ LicenseStatus = [LicenseStatusCode]::Licensed; Activated = $true }
        }

        { Invoke-OfflineActivation -CimSession $script:MockCimSession -Service $script:Service `
                -ConfirmationId ('1' * 54) } | Should -Not -Throw

        Should -Invoke Invoke-SppCimMethod -Times 0
        Should -Invoke Get-WindowsLicensingProduct -Times 0
        Should -Invoke Get-OfflineInstallationId -Times 0
    }

    It 'refreshes and verifies the final license status' {
        Invoke-OfflineActivation -CimSession $script:MockCimSession -Service $script:Service `
            -ConfirmationId ('1' * 54)

        Should -Invoke Invoke-SppCimMethod -ParameterFilter { $MethodName -eq 'RefreshLicenseStatus' } -Times 1
        Should -Invoke Get-LicenseStatus -Times 2
    }

    It 'throws when the final state is not activated' {
        Mock Get-LicenseStatus {
            [PSCustomObject]@{ LicenseStatus = [LicenseStatusCode]::Notification; Activated = $false }
        }

        { Invoke-OfflineActivation -CimSession $script:MockCimSession -Service $script:Service `
                -ConfirmationId ('1' * 54) } | Should -Throw -ExpectedMessage '*Offline activation failed*'
    }

    It 'accepts extended grace with a warning' {
        $script:StatusCall = 0
        Mock Get-LicenseStatus {
            $script:StatusCall++
            if ($script:StatusCall -eq 1)
            {
                [PSCustomObject]@{ LicenseStatus = [LicenseStatusCode]::Unlicensed; Activated = $false }
            }
            else
            {
                [PSCustomObject]@{ LicenseStatus = [LicenseStatusCode]::ExtendedGrace; Activated = $false }
            }
        }

        Invoke-OfflineActivation -CimSession $script:MockCimSession -Service $script:Service `
            -ConfirmationId ('1' * 54) -WarningVariable warning
        $warning | Should -Match 'extended grace'
    }

    It 'uses one activation ID for status, installation ID, and confirmation deposit' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        Invoke-OfflineActivation -CimSession $script:MockCimSession -Service $script:Service `
            -ConfirmationId ('1' * 54) -ActivationId $activationId

        Should -Invoke Get-LicenseStatus -Times 2 -ParameterFilter {
            $ActivationId -eq $activationId
        }
        Should -Invoke Get-WindowsLicensingProduct -Times 1 -ParameterFilter {
            $ActivationId -eq $activationId
        }
        Should -Invoke Get-OfflineInstallationId -Times 1 -ParameterFilter {
            $Product -eq $script:Product
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'DepositOfflineConfirmationId' -and $InputObject -eq $script:Product
        }
    }
}
