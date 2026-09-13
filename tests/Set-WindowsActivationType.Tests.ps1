BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Set-WindowsActivationType' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
        $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            ID   = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            Name = 'Windows'
        }

        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Get-CimInstance -ModuleName slmgr-ps { $script:Service }
        Mock Get-WindowsLicensingProduct -ModuleName slmgr-ps { $script:Product }
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {}
        Mock Remove-CimSession -ModuleName slmgr-ps {}
    }

    It 'maps Any to the clear method' {
        $result = Set-WindowsActivationType -ActivationType Any -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'ClearVLActivationTypeEnabled' -and $InputObject -eq $script:Service
        }
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 0 -ParameterFilter {
            $MethodName -eq 'SetVLActivationTypeEnabled'
        }
        $result.Operation | Should -Be 'SetActivationType'
        $result.Success | Should -BeTrue
        $result.VerificationState | Should -Be 'ProviderAccepted'
    }

    It 'maps ActiveDirectory to provider value 1' {
        Set-WindowsActivationType -ActivationType ActiveDirectory -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetVLActivationTypeEnabled' -and $Arguments.ActivationType -eq 1
        }
    }

    It 'maps Kms to provider value 2' {
        Set-WindowsActivationType -ActivationType Kms -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetVLActivationTypeEnabled' -and $Arguments.ActivationType -eq 2
        }
    }

    It 'maps Token to provider value 3' {
        Set-WindowsActivationType -ActivationType Token -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetVLActivationTypeEnabled' -and $Arguments.ActivationType -eq 3
        }
    }

    It 'targets an exact licensing product when ActivationId is supplied' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $result = Set-WindowsActivationType -ActivationType Kms `
            -ActivationId $activationId -Confirm:$false

        Should -Invoke Get-WindowsLicensingProduct -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $ActivationId -eq $activationId -and $ErrorAction -eq 'Stop'
        }
        Should -Invoke Get-CimInstance -ModuleName slmgr-ps -Times 0
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetVLActivationTypeEnabled' -and $InputObject -eq $script:Product
        }
        $result.ActivationId | Should -Be $activationId
        $result.ProductName | Should -Be 'Windows'
    }

    It 'does not open a session under WhatIf' {
        Set-WindowsActivationType -ActivationType Kms -WhatIf

        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 0
    }

    It 'rejects unsupported activation type values before opening a session' {
        { Set-WindowsActivationType -ActivationType Invalid -Confirm:$false } | Should -Throw
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'continues the computer batch and throws one aggregate error' {
        $script:Calls = 0
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {
            $script:Calls++
            if ($script:Calls -eq 1) { throw 'First policy change failed' }
        }

        $caught = $null
        try
        {
            Set-WindowsActivationType -Computer WS01, WS02 -ActivationType Kms `
                -Confirm:$false -ErrorAction Stop
        }
        catch
        {
            $caught = $_
        }

        $caught.FullyQualifiedErrorId | Should -Match '^LicensingBatchFailed'
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 2
        Should -Invoke Remove-CimSession -ModuleName slmgr-ps -Times 2
    }
}
