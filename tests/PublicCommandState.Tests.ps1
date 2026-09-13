BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Public command state' {
    It 'does not require elevation to import the module' {
        Get-Module slmgr-ps | Should -Not -BeNullOrEmpty
        $expectedCommands = @(
            'Get-WindowsActivation'
            'Get-WindowsADActivationInstallationId'
            'Get-WindowsADActivationObject'
            'Get-WindowsTokenActivationLicense'
            'Install-WindowsLicense'
            'New-WindowsADActivationObject'
            'Remove-WindowsADActivationObject'
            'Remove-WindowsTokenActivationLicense'
            'Repair-WindowsLicense'
            'Reset-WindowsActivation'
            'Set-WindowsActivationType'
            'Set-WindowsKmsClient'
            'Start-WindowsActivation'
        )
        $actualCommands = @(Get-Command -Module slmgr-ps).Name

        $actualCommands.Count | Should -Be $expectedCommands.Count
        foreach ($command in $expectedCommands)
        {
            $actualCommands | Should -Contain $command
        }
    }

    It 'does not place administrator requirements on public script files' {
        $publicScripts = Get-ChildItem $PSScriptRoot/../src/Public -Filter '*.ps1'
        foreach ($script in $publicScripts)
        {
            Get-Content $script.FullName -Raw | Should -Not -Match '#Requires\s+-RunAsAdministrator'
        }
    }

    It 'preserves ErrorActionPreference when a license query fails' {
        $previousPreference = $ErrorActionPreference
        try
        {
            $session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
            Mock Get-Session -ModuleName slmgr-ps { $session }
            Mock Remove-CimSession -ModuleName slmgr-ps {}
            Mock Get-CimInstance -ModuleName slmgr-ps { throw 'License query failed' }

            $ErrorActionPreference = 'Continue'
            { Get-WindowsActivation } | Should -Throw -ExpectedMessage '*License query failed*'
            $ErrorActionPreference | Should -Be 'Continue'
            Should -Invoke Get-CimInstance -ModuleName slmgr-ps -ParameterFilter {
                $ErrorAction -eq 'Stop'
            } -Times 1
        }
        finally
        {
            $ErrorActionPreference = $previousPreference
        }
    }
}
