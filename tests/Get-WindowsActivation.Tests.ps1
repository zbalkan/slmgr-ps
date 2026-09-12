BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Get-WindowsActivation product targeting' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly

        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Remove-CimSession -ModuleName slmgr-ps {}
        Mock Get-WindowsLicensingProduct -ModuleName slmgr-ps { $script:Product }
        Mock Get-BasicLicenseInformation -ModuleName slmgr-ps { [PSCustomObject]@{ View = 'Basic' } }
        Mock Get-ExtendedLicenseInformation -ModuleName slmgr-ps { [PSCustomObject]@{ View = 'Extended' } }
        Mock Get-ExpiryInformation -ModuleName slmgr-ps { [PSCustomObject]@{ View = 'Expiry' } }
        Mock Get-OfflineInstallationId -ModuleName slmgr-ps { [PSCustomObject]@{ View = 'Offline' } }
    }

    It 'resolves an activation ID once and passes the product to the basic formatter' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        $result = Get-WindowsActivation -ActivationId $activationId

        $result.View | Should -Be 'Basic'
        Should -Invoke Get-WindowsLicensingProduct -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $ActivationId -eq $activationId -and $ErrorAction -eq 'Stop'
        }
        Should -Invoke Get-BasicLicenseInformation -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $Product -eq $script:Product -and $ErrorAction -eq 'Stop'
        }
    }

    It 'supports activation ID targeting for each detailed read mode' -ForEach @(
        @{ Switch = 'Extended'; Helper = 'Get-ExtendedLicenseInformation'; View = 'Extended' }
        @{ Switch = 'Expiry'; Helper = 'Get-ExpiryInformation'; View = 'Expiry' }
        @{ Switch = 'Offline'; Helper = 'Get-OfflineInstallationId'; View = 'Offline' }
    ) {
        $activationId = [Guid]'11111111-2222-3333-4444-555555555555'
        $parameters = @{ ActivationId = $activationId; $Switch = $true }

        $result = Get-WindowsActivation @parameters

        $result.View | Should -Be $View
        Should -Invoke $Helper -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $Product -eq $script:Product
        }
    }

    It 'rejects a malformed activation ID before opening a session' {
        { Get-WindowsActivation -ActivationId 'not-a-guid' } | Should -Throw

        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }
}
