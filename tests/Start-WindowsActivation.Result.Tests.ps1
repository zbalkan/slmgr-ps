BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Start-WindowsActivation result contract' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Get-CimInstance -ModuleName slmgr-ps { $script:Service }
        Mock Remove-CimSession -ModuleName slmgr-ps {}
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {}
    }

    It 'returns a verified activation result' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Mock Invoke-KMSActivation -ModuleName slmgr-ps {
            [PSCustomObject]@{
                ActivationId      = $activationId
                ProductName       = 'Windows'
                VerificationState = 'Verified'
                RestartRequired   = $false
            }
        }

        $result = Start-WindowsActivation -Confirm:$false

        $result.PSObject.TypeNames[0] | Should -Be 'slmgr-ps.LicensingOperationResult'
        $result.Success | Should -BeTrue
        $result.Operation | Should -Be 'Activate'
        $result.ActivationId | Should -Be $activationId
        $result.ProductName | Should -Be 'Windows'
        $result.RestartRequired | Should -BeFalse
        $result.VerificationState | Should -Be 'Verified'
    }

    It 'marks rearm as restart-required and provider-accepted' {
        Mock Invoke-Rearm -ModuleName slmgr-ps {
            [PSCustomObject]@{
                ActivationId      = $null
                ProductName       = $null
                VerificationState = 'ProviderAccepted'
                RestartRequired   = $true
            }
        }

        $result = Start-WindowsActivation -Rearm -Confirm:$false

        $result.Success | Should -BeTrue
        $result.Operation | Should -Be 'RearmWindows'
        $result.RestartRequired | Should -BeTrue
        $result.VerificationState | Should -Be 'ProviderAccepted'
    }

    It 'retains the requested activation ID on a failed targeted activation' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Mock Invoke-KMSActivation -ModuleName slmgr-ps { throw 'Activation failed' }

        $caught = $null
        try
        {
            Start-WindowsActivation -ActivationId $activationId -Confirm:$false -ErrorAction Stop
        }
        catch
        {
            $caught = $_
        }

        $caught.FullyQualifiedErrorId | Should -Match '^LicensingBatchFailed'
        $failed = @($caught.TargetObject)[0]
        $failed.Success | Should -BeFalse
        $failed.Operation | Should -Be 'Activate'
        $failed.ActivationId | Should -Be $activationId
        $failed.VerificationState | Should -Be 'Failed'
    }
}
