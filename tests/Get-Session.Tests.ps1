BeforeAll {
    . $PSScriptRoot/../src/Private/Get-Session.ps1
    $script:MockSession = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
}

Describe 'Get-Session' {
    BeforeEach {
        Mock New-CimSessionOption { [PSCustomObject]@{ Protocol = 'Dcom' } }
        Mock New-CimSession { $script:MockSession }
    }

    It 'uses DCOM for a local session' {
        Get-Session -Computer localhost | Should -Be $script:MockSession
        Should -Invoke New-CimSessionOption -ParameterFilter { $Protocol -eq 'Dcom' } -Times 1
        Should -Invoke New-CimSession -ParameterFilter { $Name -eq 'SlmgrLocalSession' } -Times 1
    }

    It 'uses the remote session path for a named computer' {
        Get-Session -Computer WS01 | Should -Be $script:MockSession
        Should -Invoke New-CimSessionOption -Times 0
        Should -Invoke New-CimSession -ParameterFilter {
            $ComputerName -eq 'WS01' -and $Name -eq 'SlmgrRemoteSession'
        } -Times 1
    }

    It 'passes credentials to a remote session' {
        $credential = [PSCredential]::new('DOMAIN\user', (ConvertTo-SecureString 'test' -AsPlainText -Force))
        Get-Session -Computer WS01 -Credentials $credential | Should -Be $script:MockSession
        Should -Invoke New-CimSession -ParameterFilter { $Credential.UserName -eq 'DOMAIN\user' } -Times 1
    }

    It 'propagates session creation failures' {
        Mock New-CimSession { throw 'Session failed' }
        { Get-Session -Computer WS01 } | Should -Throw -ExpectedMessage '*Session failed*'
    }
}
