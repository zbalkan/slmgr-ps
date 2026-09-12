BeforeAll {
    . $PSScriptRoot/../src/Private/Invoke-ProductKeyInstallation.ps1

    function Invoke-SppCimMethod {}

    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
}

Describe 'Invoke-ProductKeyInstallation' {
    BeforeEach {
        Mock Invoke-SppCimMethod {}
    }

    It 'installs the supplied key through SoftwareLicensingService' {
        Invoke-ProductKeyInstallation -Service $script:Service `
            -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'

        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'InstallProductKey' -and
            $Arguments.ProductKey -eq 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' -and
            $InputObject -eq $script:Service
        }
    }

    It 'refreshes license status after installation' {
        Invoke-ProductKeyInstallation -Service $script:Service `
            -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'

        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus' -and $InputObject -eq $script:Service
        }
    }

    It 'does not refresh when installation fails' {
        Mock Invoke-SppCimMethod {
            if ($MethodName -eq 'InstallProductKey') { throw 'Installation failed' }
        }

        { Invoke-ProductKeyInstallation -Service $script:Service `
                -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' } |
            Should -Throw -ExpectedMessage '*Installation failed*'

        Should -Invoke Invoke-SppCimMethod -Times 0 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus'
        }
    }
}
