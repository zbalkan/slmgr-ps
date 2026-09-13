BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Active Directory activation provider contract' {
    It 'defines the documented service methods' {
        InModuleScope slmgr-ps {
            $contract = Get-SppContract
            $contract.Methods.DoActiveDirectoryOnlineActivation.Classes | Should -Contain 'SoftwareLicensingService'
            $contract.Methods.GenerateActiveDirectoryOfflineActivationId.Classes | Should -Contain 'SoftwareLicensingService'
            $contract.Methods.DepositActiveDirectoryOfflineActivationConfirmation.Classes | Should -Contain 'SoftwareLicensingService'
        }
    }

    It 'defines the documented input arguments' {
        InModuleScope slmgr-ps {
            $methods = (Get-SppContract).Methods
            $methods.DoActiveDirectoryOnlineActivation.Arguments | Should -Be @('ProductKey', 'ActivationObjectName')
            $methods.GenerateActiveDirectoryOfflineActivationId.Arguments | Should -Be @('ProductKey')
            $methods.DepositActiveDirectoryOfflineActivationConfirmation.Arguments | Should -Be @('ProductKey', 'ConfirmationID', 'ActivationObjectName')
        }
    }

    It 'exposes Active Directory activation metadata' {
        InModuleScope slmgr-ps {
            $properties = (Get-SppContract).ProductProperties
            $properties | Should -Contain 'ADActivationObjectName'
            $properties | Should -Contain 'ADActivationObjectDN'
            $properties | Should -Contain 'ADActivationCsvlkPid'
            $properties | Should -Contain 'ADActivationCsvlkSkuId'
        }
    }
}
