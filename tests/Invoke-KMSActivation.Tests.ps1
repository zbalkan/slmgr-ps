BeforeAll {
    . $PSScriptRoot/../src/Private/Invoke-KMSActivation.ps1

    function Get-LicenseStatus
    {
        param($CimSession, [Guid]$ActivationId)
    }
    function Get-KMSKey
    {
        param($CimSession)
    }
    function Get-WindowsLicensingProduct
    {
        param($CimSession, [Guid]$ActivationId, [string]$PartialProductKey)
    }
    function Invoke-SppCimMethod
    {
        param(
            [Parameter(ValueFromPipeline)]$InputObject,
            [string]$MethodName,
            [hashtable]$Arguments
        )
    }

    $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
    $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly -Property @{
        ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    }
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
        Should -Invoke Get-WindowsLicensingProduct -Times 1 -ParameterFilter {
            $PartialProductKey -eq 'EEEEE'
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'Activate' -and $InputObject -eq $script:Product
        }
        Should -Invoke Get-KMSKey -Times 0
        Should -Invoke Get-LicenseStatus -Times 1
        Should -Invoke Get-LicenseStatus -Times 1 -ParameterFilter {
            $ActivationId -eq [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }
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

    It 'rejects service-scoped key installation combined with product targeting' {
        { Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
                -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' `
                -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' } |
            Should -Throw -ExpectedMessage '*InstallProductKey is service-scoped*'

        Should -Invoke Get-WindowsLicensingProduct -Times 0
        Should -Invoke Get-LicenseStatus -Times 0
        Should -Invoke Invoke-SppCimMethod -Times 0
    }

    It 'does not activate when the installed product cannot be resolved' {
        Mock Get-WindowsLicensingProduct { throw 'Installed product was not found.' }

        { Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
                -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' } |
            Should -Throw -ExpectedMessage '*Installed product was not found*'

        Should -Invoke Invoke-SppCimMethod -Times 0 -ParameterFilter {
            $MethodName -eq 'Activate'
        }
        Should -Invoke Get-LicenseStatus -Times 0
    }

    It 'does not activate when the installed product has no activation ID' {
        Mock Get-WindowsLicensingProduct {
            New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly
        }

        { Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
                -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' } |
            Should -Throw -ExpectedMessage '*has no activation ID*'

        Should -Invoke Invoke-SppCimMethod -Times 0 -ParameterFilter {
            $MethodName -eq 'Activate'
        }
        Should -Invoke Get-LicenseStatus -Times 0
    }

    It 'resolves, activates, and verifies the requested activation ID' {
        $expectedActivationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $script:StatusCall = 0
        Mock Get-LicenseStatus {
            $script:StatusCall++
            if ($script:StatusCall -eq 1)
            {
                [PSCustomObject]@{ Activated = $false; LicenseStatus = 'Unlicensed' }
            }
            else
            {
                [PSCustomObject]@{ Activated = $true; LicenseStatus = 'Licensed' }
            }
        } -ParameterFilter { $ActivationId -eq $expectedActivationId }

        Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
            -ActivationId $expectedActivationId

        Should -Invoke Get-WindowsLicensingProduct -Times 1 -ParameterFilter {
            $ActivationId -eq $expectedActivationId
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'Activate' -and $InputObject -eq $script:Product
        }
        Should -Invoke Get-LicenseStatus -Times 2 -ParameterFilter {
            $ActivationId -eq $expectedActivationId
        }
    }

    It 'applies KMS client settings to the requested activation product' {
        $expectedActivationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $script:StatusCall = 0
        Mock Get-LicenseStatus {
            $script:StatusCall++
            [PSCustomObject]@{
                Activated = $script:StatusCall -gt 1
                LicenseStatus = if ($script:StatusCall -gt 1) { 'Licensed' } else { 'Unlicensed' }
            }
        }

        Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
            -ActivationId $expectedActivationId -KMSServerFQDN 'kms.example.com' -KMSServerPort 1689

        Should -Invoke Get-WindowsLicensingProduct -Times 1 -ParameterFilter {
            $ActivationId -eq $expectedActivationId
        }

        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServiceMachine' -and
            $InputObject -eq $script:Product
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServicePort' -and
            $InputObject -eq $script:Product
        }
    }

    It 'does not skip an explicit KMS client setting when already activated' {
        Invoke-KMSActivation -CimSession $script:Session -Service $script:Service `
            -KMSServerFQDN 'kms.example.com'

        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'SetKeyManagementServiceMachine'
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'Activate'
        }
    }
}
