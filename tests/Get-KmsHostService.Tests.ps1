BeforeAll {
    . $PSScriptRoot/../src/Private/Get-KmsHostService.ps1
}

Describe 'Get-KmsHostService' {
    BeforeEach {
        $script:Session = New-MockObject -Type 'Microsoft.Management.Infrastructure.CimSession'
    }

    It 'returns an enabled KMS host service' {
        $service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly -Property @{
            IsKeyManagementServiceMachine = [uint32]1
        }
        Mock Get-CimInstance { $service }

        Get-KmsHostService -CimSession $script:Session | Should -Be $service
    }

    It 'rejects a client-only target' {
        $service = New-CimInstance -ClassName SoftwareLicensingService -ClientOnly -Property @{
            IsKeyManagementServiceMachine = [uint32]0
        }
        Mock Get-CimInstance { $service }

        { Get-KmsHostService -CimSession $script:Session } | Should -Throw -ExpectedMessage '*not enabled as a Key Management Service host*'
    }
}
