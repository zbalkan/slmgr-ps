BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Get-WindowsTokenActivationLicense' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Remove-CimSession -ModuleName slmgr-ps {}
    }

    It 'returns structured issuance-license information' {
        Mock Get-CimInstance -ModuleName slmgr-ps {
            [PSCustomObject]@{
                ID                  = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                ILID                = '11111111-2222-3333-4444-555555555555'
                ILVID               = [uint32]7
                AuthorizationStatus = [uint32]0
                ExpirationDate      = [datetime]'2030-01-02T03:04:05Z'
                Description         = 'Test issuance license'
                AdditionalInfo      = 'metadata'
            }
        }

        $result = Get-WindowsTokenActivationLicense

        $result.ComputerName | Should -Be 'localhost'
        $result.ID | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        $result.ILID | Should -Be '11111111-2222-3333-4444-555555555555'
        $result.ILVID | Should -Be 7
        $result.AuthorizationStatusCode | Should -Be 0
        $result.AuthorizationStatus | Should -Be '0x00000000'
        $result.ExpirationDate | Should -Be ([datetime]'2030-01-02T03:04:05Z')
        $result.Description | Should -Be 'Test issuance license'
        $result.AdditionalInfo | Should -Be 'metadata'
    }

    It 'returns no object when no issuance licenses are installed' {
        Mock Get-CimInstance -ModuleName slmgr-ps { @() }

        @(Get-WindowsTokenActivationLicense).Count | Should -Be 0
    }

    It 'passes credentials to the CIM session' {
        Mock Get-CimInstance -ModuleName slmgr-ps { @() }
        $credential = [PSCredential]::new('user', (ConvertTo-SecureString 'secret' -AsPlainText -Force))

        Get-WindowsTokenActivationLicense -Computer WS01 -Credentials $credential

        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $Computer -eq 'WS01' -and $Credentials -eq $credential
        }
    }
}

Describe 'Remove-WindowsTokenActivationLicense' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
        $script:License = New-CimInstance -ClassName SoftwareLicensingTokenActivationLicense `
            -ClientOnly -Property @{
                ID          = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
                ILID        = '11111111-2222-3333-4444-555555555555'
                ILVID       = [uint32]7
                Description = 'Test issuance license'
            }
        $script:QueryCount = 0

        Mock Get-Session -ModuleName slmgr-ps { $script:Session }
        Mock Remove-CimSession -ModuleName slmgr-ps {}
        Mock Get-TokenActivationLicense -ModuleName slmgr-ps {
            $script:QueryCount++
            if ($script:QueryCount -eq 1) { return $script:License }
            return @()
        }
        Mock Invoke-SppCimMethod -ModuleName slmgr-ps {}
    }

    It 'uninstalls the exact issuance license and verifies disappearance' {
        $result = Remove-WindowsTokenActivationLicense `
            -ILID 11111111-2222-3333-4444-555555555555 -ILVID 7 -Confirm:$false

        $result.Success | Should -BeTrue
        $result.Operation | Should -Be 'RemoveTokenActivationLicense'
        $result.VerificationState | Should -Be 'Verified'
        Should -Invoke Invoke-SppCimMethod -ModuleName slmgr-ps -Times 1 -ParameterFilter {
            $MethodName -eq 'Uninstall'
        }
        Should -Invoke Get-TokenActivationLicense -ModuleName slmgr-ps -Times 2
    }

    It 'does not open a session under WhatIf' {
        Remove-WindowsTokenActivationLicense `
            -ILID 11111111-2222-3333-4444-555555555555 -ILVID 7 -WhatIf

        Should -Invoke Get-Session -ModuleName slmgr-ps -Times 0
    }

    It 'fails when the exact issuance license is not found' {
        Mock Get-TokenActivationLicense -ModuleName slmgr-ps { @() }

        {
            Remove-WindowsTokenActivationLicense `
                -ILID 11111111-2222-3333-4444-555555555555 -ILVID 7 -Confirm:$false
        } | Should -Throw -ExpectedMessage '*was not found*'
    }

    It 'fails verification when the issuance license remains installed' {
        Mock Get-TokenActivationLicense -ModuleName slmgr-ps { $script:License }

        {
            Remove-WindowsTokenActivationLicense `
                -ILID 11111111-2222-3333-4444-555555555555 -ILVID 7 -Confirm:$false
        } | Should -Throw -ExpectedMessage '*remains installed*'
    }
}
