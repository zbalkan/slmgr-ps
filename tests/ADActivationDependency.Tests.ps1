BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Active Directory activation dependencies' {
    It 'fails before directory access when the ActiveDirectory module is unavailable' {
        InModuleScope slmgr-ps {
            Mock Get-Module { $null }
            Mock Import-Module {}

            { Get-ADActivationContext } | Should -Throw -ExpectedMessage '*ActiveDirectory PowerShell module*'
            Should -Invoke Import-Module -Times 0
        }
    }
}
