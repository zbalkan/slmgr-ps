BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Get-ExtendedLicenseInformation.ps1
    function Get-WindowsLicensingProduct { param($CimSession) }
}

Describe 'Get-ExtendedLicenseInformation result contract' {
    It 'preserves numeric status and reports documented product and service fields' {
        $evaluationEnd = [datetime]'2030-01-02T03:04:05Z'
        $trustedTime = [datetime]'2026-09-13T12:00:00Z'
        $product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            Name                                  = 'Windows'
            LicenseStatus                         = 1
            LicenseStatusReason                   = [uint32]0
            GracePeriodRemaining                  = [uint32]120
            EvaluationEndDate                     = $evaluationEnd
            RemainingAppReArmCount                = [uint32]4
            RemainingSkuReArmCount                = [uint32]3
            TrustedTime                           = $trustedTime
            VLActivationInterval                  = [uint32]120
            VLRenewalInterval                     = [uint32]10080
            TokenActivationILID                   = '11111111-2222-3333-4444-555555555555'
            TokenActivationILVID                  = [uint32]7
            TokenActivationGrantNumber            = [uint32]2
            TokenActivationCertificateThumbprint  = 'AABBCCDDEEFF'
            TokenActivationAdditionalInfo         = 'token metadata'
            ADActivationObjectName                = 'Forest Activation'
            ADActivationObjectDN                  = 'CN=Forest Activation,CN=Activation Objects,CN=Microsoft SPP,CN=Services,CN=Configuration,DC=example,DC=com'
            ADActivationCsvlkPid                  = 'pid-value'
            ADActivationCsvlkSkuId                = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }
        $service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly -Property @{
            Version                       = '10.0-test'
            ClientMachineID               = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            RemainingWindowsReArmCount    = [uint32]5
            IsKeyManagementServiceMachine = [uint32]0
        }

        $result = Get-ExtendedLicenseInformation -Product $product -Service $service

        $result.LicenseStatusCode | Should -Be 1
        $result.LicenseStatus.ToString() | Should -Be 'Licensed'
        $result.LicenseStatusReason | Should -Be 0
        $result.GracePeriodRemaining | Should -Be 120
        $result.EvaluationEndDate | Should -Be $evaluationEnd
        $result.RemainingWindowsRearmCount | Should -Be 5
        $result.RemainingAppRearmCount | Should -Be 4
        $result.RemainingSkuRearmCount | Should -Be 3
        $result.TrustedTime | Should -Be $trustedTime
        $result.ServiceVersion | Should -Be '10.0-test'
        $result.ClientMachineId | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $result.IsKmsHost | Should -BeFalse
        $result.VlActivationInterval | Should -Be 120
        $result.VlRenewalInterval | Should -Be 10080
        $result.TokenActivationILID | Should -Be '11111111-2222-3333-4444-555555555555'
        $result.TokenActivationILVID | Should -Be 7
        $result.TokenActivationGrantNumber | Should -Be 2
        $result.TokenActivationCertificateThumbprint | Should -Be 'AABBCCDDEEFF'
        $result.TokenActivationAdditionalInfo | Should -Be 'token metadata'
        $result.ADActivationObjectName | Should -Be 'Forest Activation'
        $result.ADActivationObjectDN | Should -Match '^CN=Forest Activation,'
        $result.ADActivationCsvlkPid | Should -Be 'pid-value'
        $result.ADActivationCsvlkSkuId | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    }

    It 'keeps unset provider dates and unavailable service properties null' {
        $product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            LicenseStatus      = 0
            TrustedTime        = [datetime]::MinValue
            EvaluationEndDate  = [datetime]::MinValue
        }
        $service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly

        $result = Get-ExtendedLicenseInformation -Product $product -Service $service

        $result.TrustedTime | Should -BeNullOrEmpty
        $result.EvaluationEndDate | Should -BeNullOrEmpty
        $result.ServiceVersion | Should -BeNullOrEmpty
        $result.ClientMachineId | Should -BeNullOrEmpty
        $result.RemainingWindowsRearmCount | Should -BeNullOrEmpty
        $result.IsKmsHost | Should -BeNullOrEmpty
    }
}
