BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Set-WindowsKmsHost' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly -Property @{
            IsKeyManagementServiceMachine     = [uint32]1
            KeyManagementServiceListeningPort = [uint32]2500
            VLActivationInterval              = [uint32]60
            VLRenewalInterval                 = [uint32]1440
            KeyManagementServiceDnsPublishing = $false
            KeyManagementServiceLowPriority   = $true
        }

        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Get-KmsHostService -ModuleName slmgr-ps { $script:Service }
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {}
        Mock Remove-CimSession -ModuleName slmgr-ps {}
    }

    It 'applies host settings through the documented provider methods' {
        $results = @(Set-WindowsKmsHost -ListeningPort 2500 -ActivationInterval 60 `
                -RenewalInterval 1440 -DnsPublishing Disabled -Priority Low -Confirm:$false)

        $results.Count | Should -Be 5
        @($results.VerificationState | Select-Object -Unique) | Should -Be 'Verified'
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServiceListeningPort' -and $Arguments.PortNumber -eq 2500
        }
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetVLActivationInterval' -and $Arguments.ActivationInterval -eq 60
        }
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'SetVLRenewalInterval' -and $Arguments.RenewalInterval -eq 1440
        }
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'DisableKeyManagementServiceDnsPublishing' -and $Arguments.DisablePublishing
        }
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'EnableKeyManagementServiceLowPriority' -and $Arguments.EnableLowPriority
        }
    }

    It 'maps normal priority and enabled DNS publishing to false provider switches' {
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly -Property @{
            IsKeyManagementServiceMachine     = [uint32]1
            KeyManagementServiceDnsPublishing = $true
            KeyManagementServiceLowPriority   = $false
        }

        Set-WindowsKmsHost -DnsPublishing Enabled -Priority Normal -Confirm:$false | Out-Null

        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'DisableKeyManagementServiceDnsPublishing' -and -not $Arguments.DisablePublishing
        }
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'EnableKeyManagementServiceLowPriority' -and -not $Arguments.EnableLowPriority
        }
    }

    It 'clears the listening-port override through the host-only clear method' {
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly -Property @{
            IsKeyManagementServiceMachine     = [uint32]1
            KeyManagementServiceListeningPort = [uint32]0
        }

        $result = Set-WindowsKmsHost -ClearListeningPort -Confirm:$false

        $result.Operation | Should -Be 'ClearKmsHostListeningPort'
        $result.VerificationState | Should -Be 'Verified'
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'ClearKeyManagementServiceListeningPort'
        }
    }

    It 'does not open a session under WhatIf' {
        Set-WindowsKmsHost -ListeningPort 2500 -WhatIf

        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 0
    }

    It 'rejects conflicting listening-port options before opening a session' {
        { Set-WindowsKmsHost -ListeningPort 2500 -ClearListeningPort -Confirm:$false } | Should -Throw
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'rejects calls with no host setting before opening a session' {
        { Set-WindowsKmsHost -Confirm:$false } | Should -Throw
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'rejects a non-host target before invoking a host method' {
        Mock Get-KmsHostService -ModuleName slmgr-ps { throw 'The target is not enabled as a Key Management Service host.' }

        { Set-WindowsKmsHost -ListeningPort 2500 -Confirm:$false -ErrorAction Stop } | Should -Throw -ExpectedMessage '*not enabled as a Key Management Service host*'
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 0
    }
}
