BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Set-WindowsKmsClient result contract' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
        $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
            Name = 'Windows'
            ID   = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }

        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Get-CimInstance -ModuleName slmgr-ps { $script:Service }
        Mock Get-WindowsLicensingProduct -ModuleName slmgr-ps { $script:Product }
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {}
        Mock Remove-CimSession -ModuleName slmgr-ps {}
    }

    It 'returns a provider-accepted result for a service-scoped change' {
        $result = Set-WindowsKmsClient -Port 2500 -Confirm:$false

        $result.PSObject.TypeNames[0] | Should -Be 'slmgr-ps.LicensingOperationResult'
        $result.ComputerName | Should -Be 'localhost'
        $result.Success | Should -BeTrue
        $result.Operation | Should -Be 'SetKmsPort'
        $result.ActivationId | Should -BeNullOrEmpty
        $result.ProductName | Should -BeNullOrEmpty
        $result.RestartRequired | Should -BeFalse
        $result.VerificationState | Should -Be 'ProviderAccepted'
    }

    It 'returns activation identity for a product-scoped change' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $result = Set-WindowsKmsClient -LookupDomain activation.example.test `
            -ActivationId $activationId -Confirm:$false

        $result.Success | Should -BeTrue
        $result.Operation | Should -Be 'SetKmsLookupDomain'
        $result.ActivationId | Should -Be $activationId
        $result.ProductName | Should -Be 'Windows'
    }

    It 'emits failed results and throws one aggregate batch error after all targets' {
        $script:Calls = 0
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {
            $script:Calls++
            if ($script:Calls -eq 1) { throw 'First computer failed' }
        }

        $output = @()
        $caught = $null
        try
        {
            $output = @(Set-WindowsKmsClient -Computer WS01, WS02 -HostCaching Disabled `
                    -Confirm:$false -ErrorAction Stop)
        }
        catch
        {
            $caught = $_
            $output = @($caught.TargetObject) + $output
        }

        $caught | Should -Not -BeNullOrEmpty
        $caught.FullyQualifiedErrorId | Should -Match '^LicensingBatchFailed'
        @($caught.TargetObject).Count | Should -Be 1
        $failed = @($caught.TargetObject)[0]
        $failed.ComputerName | Should -Be 'WS01'
        $failed.Success | Should -BeFalse
        $failed.Operation | Should -Be 'SetKmsHostCaching'
        $failed.VerificationState | Should -Be 'Failed'
        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 2
        Should -Invoke Remove-CimSession -ModuleName slmgr-ps -Times 2
    }
}
