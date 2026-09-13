BeforeAll {
    . $PSScriptRoot/../src/Public/Start-WindowsActivation.ps1

    function Get-Session {}
    function Invoke-OfflineActivation {}
    function Invoke-KMSActivation {}
    function Invoke-Rearm {}

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
        $expectedActivationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        Start-WindowsActivation -ActivationId $expectedActivationId -Confirm:$false

        Should -Invoke Invoke-KMSActivation -Times 1 -ParameterFilter {
            $ActivationId -eq $expectedActivationId
        }
    }

    It 'rejects a malformed activation ID before opening a session' {
        { Start-WindowsActivation -ActivationId 'not-a-guid' -Confirm:$false } | Should -Throw

        Should -Invoke Get-Session -Times 0
    }

    It 'forwards an activation ID to offline activation' {
        $expectedActivationId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Mock Invoke-OfflineActivation {}

        Start-WindowsActivation -Offline -ConfirmationId ('1' * 54) `
            -ActivationId $expectedActivationId -Confirm:$false

        Should -Invoke Invoke-OfflineActivation -Times 1 -ParameterFilter {
            $ActivationId -eq $expectedActivationId
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
        $expectedApplicationId = [Guid]'11111111-2222-3333-4444-555555555555'

        Start-WindowsActivation -Rearm -ApplicationId $expectedApplicationId -Confirm:$false

        Should -Invoke Invoke-Rearm -Times 1 -ParameterFilter {
            $ApplicationId -eq $expectedApplicationId -and
            -not $PSBoundParameters.ContainsKey('ActivationId')
        }
    }

    It 'forwards an activation ID to SKU rearm' {
        $expectedSkuId = [Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        Start-WindowsActivation -Rearm -ActivationId $expectedSkuId -Confirm:$false

        Should -Invoke Invoke-Rearm -Times 1 -ParameterFilter {
            $ActivationId -eq $expectedSkuId -and
            -not $PSBoundParameters.ContainsKey('ApplicationId')
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
