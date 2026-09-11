BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Public command state' {
    It 'does not require elevation to import the module' {
        Get-Module slmgr-ps | Should -Not -BeNullOrEmpty
        Get-Command Get-WindowsActivation -Module slmgr-ps | Should -Not -BeNullOrEmpty
    }

    It 'does not place administrator requirements on public script files' {
        $publicScripts = Get-ChildItem $PSScriptRoot/../src/Public -Filter '*.ps1'
        foreach ($script in $publicScripts)
        {
            Get-Content $script.FullName -Raw | Should -Not -Match '#Requires\s+-RunAsAdministrator'
        }
    }

    It 'preserves ErrorActionPreference when validation fails' {
        $previousPreference = $ErrorActionPreference
        try
        {
            $ErrorActionPreference = 'Continue'
            { Reset-WindowsActivation -Confirm:$false } | Should -Throw
            $ErrorActionPreference | Should -Be 'Continue'
        }
        finally
        {
            $ErrorActionPreference = $previousPreference
        }
    }
}
