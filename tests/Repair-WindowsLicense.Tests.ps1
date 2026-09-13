BeforeAll {
    . $PSScriptRoot/../src/Private/New-LicensingOperationResult.ps1
    . $PSScriptRoot/../src/Private/New-LicensingOperationError.ps1
    . $PSScriptRoot/../src/Private/Complete-LicensingOperationBatch.ps1
    . $PSScriptRoot/../src/Public/Repair-WindowsLicense.ps1

    function Get-SystemLicenseFile {}
    function Get-LicenseFileContent { param([string[]]$Path) }
    function Get-Session { param($Computer, $Credentials) }
    function Invoke-SppCimMethod
    {
        param(
            [Parameter(ValueFromPipeline)]$InputObject,
            [string]$MethodName,
            [hashtable]$Arguments
        )
    }

    $script:MockCimSession = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
}

Describe 'Repair-WindowsLicense' {
    BeforeEach {
        Mock Get-SystemLicenseFile {
            @(
                [PSCustomObject]@{ FullName = 'C:\Windows\System32\oem\one.xrm-ms' }
                [PSCustomObject]@{ FullName = 'C:\Windows\System32\spp\tokens\two.xrm-ms' }
            )
        }
        Mock Get-LicenseFileContent {
            [PSCustomObject]@{ Path = $Path[0]; Content = "content:$($Path[0])" }
        }
        Mock Get-Session { $script:MockCimSession }
        Mock Get-CimInstance { $script:Service }
        Mock Invoke-SppCimMethod {}
        Mock Remove-CimSession {}
    }

    It 'reinstalls every discovered license and refreshes once' {
        Repair-WindowsLicense -Confirm:$false

        Should -Invoke Get-LicenseFileContent -Times 2
        Should -Invoke Invoke-SppCimMethod -Times 2 -ParameterFilter {
            $MethodName -eq 'InstallLicense'
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus'
        }
        Should -Invoke Remove-CimSession -Times 1
    }

    It 'uses a local CIM session without credentials' {
        Repair-WindowsLicense -Confirm:$false

        Should -Invoke Get-Session -Times 1 -ParameterFilter {
            $Computer -eq 'localhost' -and $null -eq $Credentials
        }
    }

    It 'does not open a session under WhatIf' {
        Repair-WindowsLicense -WhatIf

        Should -Invoke Get-SystemLicenseFile -Times 1
        Should -Invoke Get-Session -Times 0
        Should -Invoke Invoke-SppCimMethod -Times 0
    }

    It 'fails before opening a session when no system licenses are found' {
        Mock Get-SystemLicenseFile { throw 'No system licenses' }

        { Repair-WindowsLicense -Confirm:$false } |
            Should -Throw -ExpectedMessage '*No system licenses*'

        Should -Invoke Get-Session -Times 0
    }

    It 'continues after a license file cannot be read' {
        Mock Get-LicenseFileContent {
            if ($Path[0] -like '*one.xrm-ms') { throw 'Read failed' }
            [PSCustomObject]@{ Path = $Path[0]; Content = 'license-two' }
        }

        { Repair-WindowsLicense -Confirm:$false -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Read failed*'

        Should -Invoke Get-LicenseFileContent -Times 2
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'InstallLicense' -and $Arguments.License -eq 'license-two'
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus'
        }
    }

    It 'continues after the provider rejects one license' {
        Mock Invoke-SppCimMethod {
            if ($MethodName -eq 'InstallLicense' -and $Arguments.License -like '*one.xrm-ms')
            {
                throw 'Provider rejected license'
            }
        }

        { Repair-WindowsLicense -Confirm:$false -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Provider rejected license*'

        Should -Invoke Invoke-SppCimMethod -Times 2 -ParameterFilter {
            $MethodName -eq 'InstallLicense'
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus'
        }
    }

    It 'removes the CIM session after a provider failure' {
        Mock Invoke-SppCimMethod {
            if ($MethodName -eq 'InstallLicense') { throw 'Provider failed' }
        }

        { Repair-WindowsLicense -Confirm:$false -ErrorAction SilentlyContinue } | Should -Throw

        Should -Invoke Remove-CimSession -Times 1
    }
}
