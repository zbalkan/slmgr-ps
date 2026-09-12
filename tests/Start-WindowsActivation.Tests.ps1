BeforeAll {
    . $PSScriptRoot/../src/Public/Start-WindowsActivation.ps1

    function Get-Session {}
    function Invoke-OfflineActivation {}
    function Invoke-KMSActivation {}

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
}
