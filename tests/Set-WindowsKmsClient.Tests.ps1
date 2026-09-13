BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Set-WindowsKmsClient' {
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

    It 'sets a normalized KMS endpoint on the licensing service' {
        Set-WindowsKmsClient -KmsServer 'kms01.example.test:2500' -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServiceMachine' -and
            $Arguments.MachineName -eq 'kms01.example.test'
        }
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServicePort' -and $Arguments.PortNumber -eq 2500
        }
    }

    It 'sets an endpoint on the exact licensing product' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Set-WindowsKmsClient -KmsServer kms01 -ActivationId $activationId -Confirm:$false

        Should -Invoke Get-WindowsLicensingProduct -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $ActivationId -eq $activationId -and $ErrorAction -eq 'Stop'
        }
        Should -Invoke Get-CimInstance -ModuleName slmgr-ps -Times 0
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 2 -ParameterFilter {
            $InputObject -eq $script:Product
        }
    }

    It 'sets only the KMS port when no server is supplied' {
        Set-WindowsKmsClient -Port 2500 -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServicePort' -and
            $Arguments.PortNumber -eq 2500
        }
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 0 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServiceMachine'
        }
    }

    It 'sets only the KMS port on the exact licensing product' {
        Set-WindowsKmsClient -Port 2500 `
            -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false

        Should -Invoke Get-CimInstance -ModuleName slmgr-ps -Times 0
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServicePort' -and
            $InputObject -eq $script:Product
        }
    }

    It 'sets a KMS lookup domain on the licensing service' {
        Set-WindowsKmsClient -LookupDomain activation.example.test -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServiceLookupDomain' -and
            $Arguments.LookupDomain -eq 'activation.example.test'
        }
    }

    It 'sets a KMS lookup domain on the exact licensing product' {
        Set-WindowsKmsClient -LookupDomain activation.example.test `
            -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false

        Should -Invoke Get-WindowsLicensingProduct -ModuleName slmgr-ps -Times 1
        Should -Invoke Get-CimInstance -ModuleName slmgr-ps -Times 0
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServiceLookupDomain' -and
            $InputObject -eq $script:Product
        }
    }

    It 'disables service-wide KMS host caching' {
        Set-WindowsKmsClient -HostCaching Disabled -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'DisableKeyManagementServiceHostCaching' -and
            $Arguments.DisableCaching -eq $true -and $InputObject -eq $script:Service
        }
    }

    It 'enables service-wide KMS host caching' {
        Set-WindowsKmsClient -HostCaching Enabled -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'DisableKeyManagementServiceHostCaching' -and
            $Arguments.DisableCaching -eq $false
        }
    }

    It 'rejects an invalid endpoint before opening a session' {
        { Set-WindowsKmsClient -KmsServer '2001:db8::10' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*must be enclosed in brackets*'
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'rejects duplicate port forms before opening a session' {
        { Set-WindowsKmsClient -KmsServer 'kms01:1688' -Port 2500 -Confirm:$false } |
            Should -Throw -ExpectedMessage '*either in Endpoint or with Port*'
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'rejects an invalid lookup domain before opening a session' {
        { Set-WindowsKmsClient -LookupDomain activation -Confirm:$false } |
            Should -Throw -ExpectedMessage '*Invalid KMS lookup domain*'
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'does not open a session under WhatIf' {
        Set-WindowsKmsClient -HostCaching Disabled -WhatIf
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'does not allow activation-ID targeting for service-wide host caching' {
        { Set-WindowsKmsClient -HostCaching Disabled `
                -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false } |
            Should -Throw
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'removes the session and reports a provider failure' {
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps { throw 'Provider failure' }

        { Set-WindowsKmsClient -HostCaching Disabled -Confirm:$false -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Provider failure*'
        Should -Invoke Remove-CimSession -ModuleName slmgr-ps -Times 1
    }

    It 'processes the full computer batch before throwing' {
        $script:Calls = 0
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {
            $script:Calls++
            if ($script:Calls -eq 1) { throw 'First computer failed' }
        }

        { Set-WindowsKmsClient -Computer WS01, WS02 -HostCaching Disabled `
                -Confirm:$false -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*First computer failed*'
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 2
        Should -Invoke Remove-CimSession -ModuleName slmgr-ps -Times 2
    }
}
