BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Get-WindowsKmsHost' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly -Property @{
            IsKeyManagementServiceMachine          = [uint32]1
            KeyManagementServiceListeningPort      = [uint32]0
            VLActivationInterval                   = [uint32]120
            VLRenewalInterval                      = [uint32]10080
            KeyManagementServiceDnsPublishing      = $true
            KeyManagementServiceLowPriority        = $false
            KeyManagementServiceCurrentCount       = [uint32]12
            RequiredClientCount                    = [uint32]25
            KeyManagementServiceProductKeyID       = 'kms-key-id'
            KeyManagementServiceActivationDisabled = $false
            KeyManagementServiceUnlicensedRequests = [uint32]1
            KeyManagementServiceLicensedRequests   = [uint32]2
            KeyManagementServiceOOBGraceRequests   = [uint32]3
            KeyManagementServiceOOTGraceRequests   = [uint32]4
            KeyManagementServiceNonGenuineGraceRequests = [uint32]5
            KeyManagementServiceNotificationRequests = [uint32]6
            KeyManagementServiceTotalRequests      = [uint32]21
            KeyManagementServiceFailedRequests     = [uint32]1
        }

        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Get-KmsHostService -ModuleName slmgr-ps { $script:Service }
        Mock Remove-CimSession -ModuleName slmgr-ps {}
    }

    It 'reports configured state and documented defaults separately' {
        $result = Get-WindowsKmsHost

        $result.PSObject.TypeNames | Should -Contain 'slmgr-ps.KmsHostStatus'
        $result.IsKmsHost | Should -BeTrue
        $result.ListeningPortConfigured | Should -BeFalse
        $result.ConfiguredListeningPort | Should -BeNullOrEmpty
        $result.EffectiveListeningPort | Should -Be 1688
        $result.DefaultListeningPort | Should -Be 1688
        $result.ActivationInterval | Should -Be 120
        $result.DefaultActivationInterval | Should -Be 120
        $result.RenewalInterval | Should -Be 10080
        $result.DefaultRenewalInterval | Should -Be 10080
        $result.DnsPublishing | Should -Be 'Enabled'
        $result.Priority | Should -Be 'Normal'
    }

    It 'reports an explicit listening-port override' {
        $script:Service.KeyManagementServiceListeningPort = [uint32]2500

        $result = Get-WindowsKmsHost

        $result.ListeningPortConfigured | Should -BeTrue
        $result.ConfiguredListeningPort | Should -Be 2500
        $result.EffectiveListeningPort | Should -Be 2500
    }

    It 'cleans up the CIM session' {
        Get-WindowsKmsHost | Out-Null
        Should -Invoke Remove-CimSession -ModuleName slmgr-ps -Times 1
    }
}
