BeforeAll {
    . $PSScriptRoot/../src/Private/LicenseStatusCode.ps1
    . $PSScriptRoot/../src/Private/Invoke-Rearm.ps1

    function Get-LicenseStatus {
        param([Microsoft.Management.Infrastructure.CimSession]$CimSession)
    }
    function Get-WindowsLicensingProduct {
        param(
            [Microsoft.Management.Infrastructure.CimSession]$CimSession,
            [Guid]$ActivationId
        )
    }
    function Invoke-SppCimMethod {
        param(
            [Parameter(ValueFromPipeline)]$InputObject,
            [string]$MethodName,
            [hashtable]$Arguments
        )
        process {}
    }

    $script:MockCimSession = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
    $script:Product = New-CimInstance -ClassName SoftwareLicensingProduct -ClientOnly
}

Describe 'Invoke-Rearm' {
    BeforeEach {
        Mock Get-LicenseStatus { [PSCustomObject]@{ LicenseStatus = [LicenseStatusCode]::OOBGrace } }
        Mock Get-WindowsLicensingProduct { $script:Product }
        Mock Invoke-SppCimMethod {}
    }

    It 'rearms Windows in an eligible grace state and refreshes licensing' {
        Invoke-Rearm -CimSession $script:MockCimSession -Service $script:Service

        Should -Invoke Get-LicenseStatus -Times 1
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'ReArmWindows' -and $InputObject -eq $script:Service
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus' -and $InputObject -eq $script:Service
        }
    }

    It 'does not rearm Windows outside an eligible grace state' {
        Mock Get-LicenseStatus { [PSCustomObject]@{ LicenseStatus = [LicenseStatusCode]::Licensed } }

        Invoke-Rearm -CimSession $script:MockCimSession -Service $script:Service -WarningAction SilentlyContinue

        Should -Invoke Invoke-SppCimMethod -Times 0
    }

    It 'rejects a missing license status before invoking the provider' {
        Mock Get-LicenseStatus { [PSCustomObject]@{ LicenseStatus = $null } }

        { Invoke-Rearm -CimSession $script:MockCimSession -Service $script:Service } |
            Should -Throw -ExpectedMessage '*License status cannot be collected*'

        Should -Invoke Invoke-SppCimMethod -Times 0
    }

    It 'rearms an application using the service and refreshes licensing' {
        $expectedApplicationId = [Guid]'11111111-2222-3333-4444-555555555555'

        Invoke-Rearm -CimSession $script:MockCimSession -Service $script:Service `
            -ApplicationId $expectedApplicationId

        Should -Invoke Get-LicenseStatus -Times 0
        Should -Invoke Get-WindowsLicensingProduct -Times 0
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'ReArmApp' -and
            $InputObject -eq $script:Service -and
            $Arguments.ApplicationId -eq $expectedApplicationId.ToString()
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus'
        }
    }

    It 'resolves and rearms exactly one SKU then refreshes licensing' {
        $expectedActivationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        Invoke-Rearm -CimSession $script:MockCimSession -Service $script:Service `
            -ActivationId $expectedActivationId

        Should -Invoke Get-LicenseStatus -Times 0
        Should -Invoke Get-WindowsLicensingProduct -Times 1 -ParameterFilter {
            $ActivationId -eq $expectedActivationId
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'ReArmSku' -and $InputObject -eq $script:Product
        }
        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'RefreshLicenseStatus'
        }
    }

    It 'rejects both identifiers before querying or mutating licensing' {
        { Invoke-Rearm -CimSession $script:MockCimSession -Service $script:Service `
                -ApplicationId '11111111-2222-3333-4444-555555555555' `
                -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' } |
            Should -Throw -ExpectedMessage '*cannot be used together*'

        Should -Invoke Get-LicenseStatus -Times 0
        Should -Invoke Get-WindowsLicensingProduct -Times 0
        Should -Invoke Invoke-SppCimMethod -Times 0
    }
}
