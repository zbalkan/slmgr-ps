BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Activation type provider contract' {
    It 'declares the set method on service and product' {
        InModuleScope slmgr-ps {
            $contract = Get-SppContract
            $contract.Methods.SetVLActivationTypeEnabled.Classes |
                Should -Be @('SoftwareLicensingService', 'SoftwareLicensingProduct')
            $contract.Methods.SetVLActivationTypeEnabled.Arguments |
                Should -Be @('ActivationType')
        }
    }

    It 'declares the clear method on service and product' {
        InModuleScope slmgr-ps {
            $contract = Get-SppContract
            $contract.Methods.ClearVLActivationTypeEnabled.Classes |
                Should -Be @('SoftwareLicensingService', 'SoftwareLicensingProduct')
            @($contract.Methods.ClearVLActivationTypeEnabled.Arguments).Count | Should -Be 0
        }
    }

    It 'declares activation type reporting properties' {
        InModuleScope slmgr-ps {
            $contract = Get-SppContract
            $contract.ProductProperties | Should -Contain 'VLActivationType'
            $contract.ProductProperties | Should -Contain 'VLActivationTypeEnabled'
        }
    }
}
