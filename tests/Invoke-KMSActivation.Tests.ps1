BeforeAll {
    . $PSScriptRoot/../src/Private/Invoke-KMSActivation.ps1

    function Get-LicenseStatus {}
    function Get-KMSKey {}
    function Get-WindowsLicensingProduct {}
    function Invoke-SppCimMethod {}

    $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
    $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly
}

Describe 'Invoke-KMSActivation product-key installation' {
    BeforeEach {
        Mock Get-LicenseStatus { [PSCustomObject]@{ Activated = $true; LicenseStatus = 'Licensed' } }
        Mock Get-KMSKey { 'FFFFF-GGGGG-HHHHH-IIIII-JJJJJ' }
        Mock Get-WindowsLicensingProduct { $script:Product }
        Mock Invoke-SppCimMethod {}
        Mock Start-Sleep {}
    }

    It 'installs an explicit key then resolves and activates the resulting product' {
        Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
            -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'

        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'InstallProductKey' -and
            $Arguments.ProductKey -eq 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'
        }
        Should -Invoke Get-WindowsLicensingProduct -Times 1
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'Activate' -and $InputObject -eq $script:Product
        }
        Should -Invoke Get-KMSKey -Times 0
        Should -Invoke Get-LicenseStatus -Times 1
    }

    It 'does not short-circuit an explicit installation when the previous product was activated' {
        Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
            -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'

        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'InstallProductKey'
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'Activate'
        }
    }

    It 'retains automatic KMS client key installation' {
        Invoke-KMSActivation -CimSession $script:Session -Service $script:Service -InstallKmsClientKey

        Should -Invoke Get-KMSKey -Times 1
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'InstallProductKey' -and
            $Arguments.ProductKey -eq 'FFFFF-GGGGG-HHHHH-IIIII-JJJJJ'
        }
    }

    It 'returns early for an already activated product when no installation was requested' {
        Invoke-KMSActivation -CimSession $script:Session -Service $script:Service

        Should -Invoke Get-LicenseStatus -Times 1
        Should -Invoke Invoke-SppCimMethod -Times 0
        Should -Invoke Get-WindowsLicensingProduct -Times 0
    }

    It 'rejects conflicting product-key sources before calling the provider' {
        { Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
                -InstallKmsClientKey -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' } |
            Should -Throw -ExpectedMessage '*cannot be used together*'

        Should -Invoke Invoke-SppCimMethod -Times 0
    }
}
