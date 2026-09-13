BeforeAll {
    . $PSScriptRoot/../src/Public/Install-WindowsLicense.ps1

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

Describe 'Install-WindowsLicense' {
    BeforeEach {
        Mock Get-LicenseFileContent {
            @(
                [PSCustomObject]@{ Path = 'C:\licenses\one.xrm-ms'; Content = 'license-one' }
                [PSCustomObject]@{ Path = 'C:\licenses\two.xrm-ms'; Content = 'license-two' }
            )
        }
        Mock Get-Session { $script:MockCimSession }
        Mock Get-CimInstance { $script:Service }
        Mock Invoke-SppCimMethod {}
        Mock Remove-CimSession {}
    }

    It 'installs every license and refreshes once per computer' {
        Install-WindowsLicense -Computer WS01, WS02 -Path 'ignored.xrm-ms' -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -Times 2 -ParameterFilter {
            $MethodName -eq 'InstallLicense' -and $Arguments.License -eq 'license-one'
        }
        Should -Invoke Invoke-SppCimMethod -Times 2 -ParameterFilter {
            $MethodName -eq 'InstallLicense' -and $Arguments.License -eq 'license-two'
        }
        Should -Invoke Invoke-SppCimMethod -Times 2 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus'
        }
        Should -Invoke Remove-CimSession -Times 2
    }

    It 'passes credentials to every session' {
        $securePassword = ConvertTo-SecureString 'password' -AsPlainText -Force
        $credential = [PSCredential]::new('DOMAIN\user', $securePassword)

        Install-WindowsLicense -Computer WS01 -Credentials $credential -Path 'ignored.xrm-ms' -Confirm:$false

        Should -Invoke Get-Session -Times 1 -ParameterFilter {
            $Computer -eq 'WS01' -and $Credentials.UserName -eq 'DOMAIN\user'
        }
    }

    It 'validates files before opening a session' {
        Mock Get-LicenseFileContent { throw 'Invalid license file' }

        { Install-WindowsLicense -Path 'bad.xrm-ms' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*Invalid license file*'

        Should -Invoke Get-Session -Times 0
    }

    It 'does not open a session under WhatIf' {
        Install-WindowsLicense -Path 'ignored.xrm-ms' -WhatIf

        Should -Invoke Get-LicenseFileContent -Times 1
        Should -Invoke Get-Session -Times 0
        Should -Invoke Invoke-SppCimMethod -Times 0
    }

    It 'continues with later files after one installation fails' {
        Mock Invoke-SppCimMethod {
            if ($MethodName -eq 'InstallLicense' -and $Arguments.License -eq 'license-one')
            {
                throw 'Provider rejected license'
            }
        }

        { Install-WindowsLicense -Computer WS01 -Path 'ignored.xrm-ms' -Confirm:$false `
                -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Provider rejected license*'

        Should -Invoke Invoke-SppCimMethod -Times 2 -ParameterFilter {
            $MethodName -eq 'InstallLicense'
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus'
        }
    }

    It 'processes every computer before honoring ErrorAction Stop' {
        Mock Invoke-SppCimMethod {
            if ($MethodName -eq 'InstallLicense') { throw 'Provider failed' }
        }

        { Install-WindowsLicense -Computer WS01, WS02 -Path 'ignored.xrm-ms' -Confirm:$false `
                -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*Provider failed*'

        Should -Invoke Get-Session -Times 2
        Should -Invoke Invoke-SppCimMethod -Times 4 -ParameterFilter {
            $MethodName -eq 'InstallLicense'
        }
        Should -Invoke Remove-CimSession -Times 2
    }

    It 'continues the batch after a session failure' {
        $script:SessionCall = 0
        Mock Get-Session {
            $script:SessionCall++
            if ($script:SessionCall -eq 1) { throw 'Session failed' }
            $script:MockCimSession
        }

        { Install-WindowsLicense -Computer WS01, WS02 -Path 'ignored.xrm-ms' -Confirm:$false `
                -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Session failed*'

        Should -Invoke Get-Session -Times 2
        Should -Invoke Invoke-SppCimMethod -Times 2 -ParameterFilter {
            $MethodName -eq 'InstallLicense'
        }
        Should -Invoke Remove-CimSession -Times 1
    }

    It 'reports a refresh failure after successful installation' {
        Mock Invoke-SppCimMethod {
            if ($MethodName -eq 'RefreshLicenseStatus') { throw 'Refresh failed' }
        }

        { Install-WindowsLicense -Computer WS01 -Path 'ignored.xrm-ms' -Confirm:$false `
                -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Refresh failed*'

        Should -Invoke Invoke-SppCimMethod -Times 2 -ParameterFilter {
            $MethodName -eq 'InstallLicense'
        }
        Should -Invoke Remove-CimSession -Times 1
    }
}
