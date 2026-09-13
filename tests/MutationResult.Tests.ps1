BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Install-WindowsLicense result contract' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
        Mock Get-LicenseFileContent -ModuleName slmgr-ps {
            [PSCustomObject]@{ Path = 'C:\licenses\one.xrm-ms'; Content = 'license-one' }
        }
        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Get-CimInstance -ModuleName slmgr-ps { $script:Service }
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {}
        Mock Remove-CimSession -ModuleName slmgr-ps {}
    }

    It 'returns one provider-accepted result per target' {
        $results = @(Install-WindowsLicense -Computer WS01, WS02 -Path ignored.xrm-ms -Confirm:$false)

        $results.Count | Should -Be 2
        $results.ComputerName | Should -Be @('WS01', 'WS02')
        $results.Operation | Should -Be @('InstallLicense', 'InstallLicense')
        $results.Success | Should -Not -Contain $false
        $results.VerificationState | Should -Be @('ProviderAccepted', 'ProviderAccepted')
    }

    It 'puts per-file details inside the failed target error' {
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps { throw 'Provider rejected license' }

        $caught = $null
        try
        {
            Install-WindowsLicense -Computer WS01 -Path ignored.xrm-ms -Confirm:$false -ErrorAction Stop
        }
        catch
        {
            $caught = $_
        }

        $caught.FullyQualifiedErrorId | Should -Match '^LicensingBatchFailed'
        $failed = @($caught.TargetObject)[0]
        $failed.ComputerName | Should -Be 'WS01'
        $failed.Operation | Should -Be 'InstallLicense'
        $failed.Success | Should -BeFalse
        $failed.VerificationState | Should -Be 'Failed'
        @($caught.Exception.Data['Failures']).Count | Should -Be 1
    }
}

Describe 'Repair-WindowsLicense result contract' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
        Mock Get-SystemLicenseFile -ModuleName slmgr-ps {
            [PSCustomObject]@{ FullName = 'C:\Windows\System32\spp\tokens\one.xrm-ms' }
        }
        Mock Get-LicenseFileContent -ModuleName slmgr-ps {
            [PSCustomObject]@{ Path = $Path[0]; Content = 'license-one' }
        }
        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Get-CimInstance -ModuleName slmgr-ps { $script:Service }
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {}
        Mock Remove-CimSession -ModuleName slmgr-ps {}
    }

    It 'returns a provider-accepted localhost result' {
        $result = Repair-WindowsLicense -Confirm:$false

        $result.ComputerName | Should -Be 'localhost'
        $result.Operation | Should -Be 'RepairSystemLicenses'
        $result.Success | Should -BeTrue
        $result.VerificationState | Should -Be 'ProviderAccepted'
    }
}

Describe 'Reset-WindowsActivation result contract' {
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

    It 'returns the product identity for a targeted reset' {
        $activationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $result = Reset-WindowsActivation -UninstallProductKey `
            -ActivationId $activationId -Confirm:$false

        $result.Operation | Should -Be 'ResetActivation'
        $result.Success | Should -BeTrue
        $result.ActivationId | Should -Be $activationId
        $result.ProductName | Should -Be 'Windows'
        $result.VerificationState | Should -Be 'ProviderAccepted'
    }
}
