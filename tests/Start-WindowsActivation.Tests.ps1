BeforeAll {
    . $PSScriptRoot/../src/Private/New-LicensingOperationResult.ps1
    . $PSScriptRoot/../src/Private/New-LicensingOperationError.ps1
    . $PSScriptRoot/../src/Private/Complete-LicensingOperationBatch.ps1
    . $PSScriptRoot/../src/Private/Resolve-KmsEndpoint.ps1
    . $PSScriptRoot/../src/Public/Start-WindowsActivation.ps1

    function Get-Session {
        param($Computer, $Credentials)
    }
    function Invoke-OfflineActivation {
        param($CimSession, $Service, [string]$ConfirmationId, [Guid]$ActivationId)
    }
    function Invoke-KMSActivation {
        param(
            $CimSession,
            $Service,
            [string]$KMSServerFQDN,
            [int]$KMSServerPort,
            [switch]$InstallKmsClientKey,
            [string]$ProductKey,
            [Guid]$ActivationId
        )
    }
    function Invoke-Rearm {
        param($CimSession, $Service, [Guid]$ApplicationId, [Guid]$ActivationId)
    }
    function Invoke-SppCimMethod {
        param(
            [Parameter(ValueFromPipeline)]$InputObject,
            [string]$MethodName,
            [hashtable]$Arguments
        )
    }

    $script:MockCimSession = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
}

Describe 'Start-WindowsActivation' {
    BeforeEach {
        $script:OfflineCall = 0
        Mock Get-Session { $script:MockCimSession }
        Mock Get-CimInstance { $script:Service }
        Mock Remove-CimSession {}
        Mock Invoke-KMSActivation {}
        Mock Invoke-Rearm {}
        Mock Invoke-OfflineActivation {
            $script:OfflineCall++
            if ($script:OfflineCall -eq 1)
            {
                throw 'Offline activation failed'
            }
        }
    }

    It 'continues a computer batch after an offline activation failure' {
        { Start-WindowsActivation -Computer WS01, WS02 -Offline -ConfirmationId ('1' * 54) `
                -Confirm:$false -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Offline activation failed*'

        Should -Invoke Invoke-OfflineActivation -Times 2
        Should -Invoke Remove-CimSession -Times 2
    }

    It 'processes the full batch before honoring ErrorAction Stop' {
        { Start-WindowsActivation -Computer WS01, WS02 -Offline -ConfirmationId ('1' * 54) `
                -Confirm:$false -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*Offline activation failed*'

        Should -Invoke Invoke-OfflineActivation -Times 2
        Should -Invoke Remove-CimSession -Times 2
    }

    It 'throws after a single-computer activation failure' {
        { Start-WindowsActivation -Computer WS01 -Offline -ConfirmationId ('1' * 54) `
                -Confirm:$false -ErrorAction SilentlyContinue } |
            Should -Throw -ExpectedMessage '*Offline activation failed*'

        Should -Invoke Invoke-OfflineActivation -Times 1
        Should -Invoke Remove-CimSession -Times 1
    }

    It 'forwards an explicit product key to the activation helper' {
        $productKey = 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'

        Start-WindowsActivation -Computer WS01 -ProductKey $productKey -Confirm:$false

        Should -Invoke Invoke-KMSActivation -Times 1 -ParameterFilter {
            $ProductKey -eq 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'
        }
    }

    It 'normalizes an embedded KMS server port before activation' {
        Start-WindowsActivation -KmsServer '[2001:db8::10]:2500' -Confirm:$false

        Should -Invoke Invoke-KMSActivation -Times 1 -ParameterFilter {
            $KMSServerFQDN -eq '2001:db8::10' -and $KMSServerPort -eq 2500
        }
    }

    It 'rejects an ambiguous KMS server before opening a session' {
        { Start-WindowsActivation -KmsServer '2001:db8::10' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*must be enclosed in brackets*'

        Should -Invoke Get-Session -Times 0
    }

    It 'passes the required Boolean when disabling KMS host caching' {
        Mock Invoke-SppCimMethod {}

        Start-WindowsActivation -CacheDisabled -Confirm:$false

        Should -Invoke Invoke-SppCimMethod -Times 1 -ParameterFilter {
            $MethodName -eq 'DisableKeyManagementServiceHostCaching' -and
            $Arguments.DisableCaching -eq $true
        }
    }

    It 'rejects a malformed product key before opening a session' {
        { Start-WindowsActivation -ProductKey 'not-a-product-key' -Confirm:$false } |
            Should -Throw -ExpectedMessage 'ProductKey must contain five groups*'

        Should -Invoke Get-Session -Times 0
    }

    It 'does not open a session for a product-key installation under WhatIf' {
        Start-WindowsActivation -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' -WhatIf

        Should -Invoke Get-Session -Times 0
        Should -Invoke Invoke-KMSActivation -Times 0
    }

    It 'rejects an explicit product key combined with automatic KMS key selection' {
        { Start-WindowsActivation -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' `
                -UseKmsClientKey -Confirm:$false } | Should -Throw -ExpectedMessage '*cannot be used together*'

        Should -Invoke Get-Session -Times 0
    }

    It 'forwards an activation ID to the activation helper' {
        Start-WindowsActivation -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false

        Should -Invoke Invoke-KMSActivation -Times 1 -ParameterFilter {
            $ActivationId -eq [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }
    }

    It 'rejects a malformed activation ID before opening a session' {
        { Start-WindowsActivation -ActivationId 'not-a-guid' -Confirm:$false } | Should -Throw

        Should -Invoke Get-Session -Times 0
    }

    It 'forwards an activation ID to offline activation' {
        Mock Invoke-OfflineActivation {}

        Start-WindowsActivation -Offline -ConfirmationId ('1' * 54) `
            -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false

        Should -Invoke Invoke-OfflineActivation -Times 1 -ParameterFilter {
            $ActivationId -eq [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }
    }

    It 'rejects an explicit key combined with activation ID before opening a session' {
        { Start-WindowsActivation -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' `
                -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*InstallProductKey is service-scoped*'

        Should -Invoke Get-Session -Times 0
    }

    It 'rejects automatic KMS key installation combined with activation ID' {
        { Start-WindowsActivation -UseKmsClientKey `
                -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*InstallProductKey is service-scoped*'

        Should -Invoke Get-Session -Times 0
    }

    It 'forwards an application ID to application rearm' {
        Start-WindowsActivation -Rearm `
            -ApplicationId '11111111-2222-3333-4444-555555555555' -Confirm:$false

        Should -Invoke Invoke-Rearm -Times 1 -ParameterFilter {
            $ApplicationId -eq [Guid]'11111111-2222-3333-4444-555555555555'
        }
    }

    It 'forwards an activation ID to SKU rearm' {
        Start-WindowsActivation -Rearm `
            -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false

        Should -Invoke Invoke-Rearm -Times 1 -ParameterFilter {
            $ActivationId -eq [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }
    }

    It 'rejects both rearm identifiers before opening a session' {
        { Start-WindowsActivation -Rearm `
                -ApplicationId '11111111-2222-3333-4444-555555555555' `
                -ActivationId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*cannot be used together*'

        Should -Invoke Get-Session -Times 0
    }

    It 'requires the rearm switch when a rearm identifier is supplied' {
        { Start-WindowsActivation `
                -ApplicationId '11111111-2222-3333-4444-555555555555' -Confirm:$false } |
            Should -Throw -ExpectedMessage '*require the Rearm switch*'

        Should -Invoke Get-Session -Times 0
    }

    It 'rejects a malformed application ID before opening a session' {
        { Start-WindowsActivation -Rearm -ApplicationId 'not-a-guid' -Confirm:$false } |
            Should -Throw

        Should -Invoke Get-Session -Times 0
    }
}
