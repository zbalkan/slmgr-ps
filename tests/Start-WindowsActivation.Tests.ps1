BeforeAll {
    . $PSScriptRoot/../src/Public/Start-WindowsActivation.ps1

    function Get-Session {}
    function Invoke-OfflineActivation {}

    $script:MockCimSession = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
    $script:Service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly
}

Describe 'Start-WindowsActivation' {
    BeforeEach {
        $script:OfflineCall = 0
        Mock Get-Session { $script:MockCimSession }
        Mock Get-CimInstance { $script:Service }
        Mock Remove-CimSession {}
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
}
