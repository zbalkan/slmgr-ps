BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Set-WindowsActivationType' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
        $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly

        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Get-CimInstance -ModuleName slmgr-ps { $script:Service }
        Mock Get-WindowsLicensingProduct -ModuleName slmgr-ps { $script:Product }
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {}
        Mock Remove-CimSession -ModuleName slmgr-ps {}
    }

    It 'maps Any to the clear method' {
        Set-WindowsActivationType -ActivationType Any -Confirm:$false
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'ClearVLActivationTypeEnabled'
        }
    }

    It 'maps Kms to provider value 2' {
        Set-WindowsActivationType -ActivationType Kms -Confirm:$false
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetVLActivationTypeEnabled' -and $Arguments.ActivationType -eq 2
        }
    }

    It 'does not open a session under WhatIf' {
        Set-WindowsActivationType -ActivationType Kms -WhatIf
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }
}
