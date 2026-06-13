BeforeAll {
    . $PSScriptRoot/../src/Private/Get-KMSKey.ps1
}

Describe 'Get-KMSKey' {

    It 'Returns correct key for Windows 11 Pro' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Pro' } }
        Get-KMSKey -CimSession $null | Should -Be 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
    }

    It 'Returns correct key for Windows 11 Pro with trailing OS suffix' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Pro 24H2' } }
        Get-KMSKey -CimSession $null | Should -Be 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
    }

    It 'Returns correct key for Windows 11 Pro N' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Pro N' } }
        Get-KMSKey -CimSession $null | Should -Be 'MH37W-N47XK-V7XM9-C7227-GCQG9'
    }

    It 'Returns correct key for Windows 11 Enterprise' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Enterprise' } }
        Get-KMSKey -CimSession $null | Should -Be 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
    }

    It 'Returns correct key for Windows 11 Enterprise N' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Enterprise N' } }
        Get-KMSKey -CimSession $null | Should -Be 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4'
    }

    It 'Returns correct key for Windows 11 Enterprise LTSC' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Enterprise LTSC 2024' } }
        Get-KMSKey -CimSession $null | Should -Be 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'
    }

    It 'Returns correct key for Windows 11 Enterprise N LTSC' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Enterprise N LTSC 2024' } }
        Get-KMSKey -CimSession $null | Should -Be '92NFX-8DJQP-P6BBQ-THF9C-7CG2H'
    }

    It 'Returns correct key for Windows 11 Education' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Education' } }
        Get-KMSKey -CimSession $null | Should -Be 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'
    }

    It 'Returns correct key for Windows 11 Education N' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Education N' } }
        Get-KMSKey -CimSession $null | Should -Be '2WH4N-8QGBV-H22JP-CT43Q-MDWWJ'
    }

    It 'Returns correct key for Windows 10 Enterprise LTSC' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 10 Enterprise LTSC' } }
        Get-KMSKey -CimSession $null | Should -Be 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'
    }

    It 'Returns correct key for Windows 10 Enterprise N LTSC' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 10 Enterprise N LTSC 2021' } }
        Get-KMSKey -CimSession $null | Should -Be '92NFX-8DJQP-P6BBQ-THF9C-7CG2H'
    }

    It 'Returns correct key for Windows Server 2025 Standard' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2025 Standard' } }
        Get-KMSKey -CimSession $null | Should -Be 'TVRH6-WHNXV-R9WG3-9XRFY-MY832'
    }

    It 'Returns correct key for Windows Server 2022 Datacenter Azure Edition' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2022 Datacenter: Azure Edition' } }
        Get-KMSKey -CimSession $null | Should -Be 'NTBV8-9K7Q8-V27C6-M2BTV-KHMXV'
    }

    It 'Does not return Azure Edition key for plain Server 2022 Datacenter' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2022 Datacenter' } }
        Get-KMSKey -CimSession $null | Should -Be 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33'
    }

    It 'Returns correct key for Windows Server 2025 Datacenter Azure Edition' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2025 Datacenter: Azure Edition' } }
        Get-KMSKey -CimSession $null | Should -Be 'XGN3F-F394H-FD2MY-PP6FD-8MCRC'
    }

    It 'Returns correct key for Windows Server 2016 Standard' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2016 Standard' } }
        Get-KMSKey -CimSession $null | Should -Be 'WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY'
    }

    It 'Returns correct key for Windows Server 2016 Datacenter' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2016 Datacenter' } }
        Get-KMSKey -CimSession $null | Should -Be 'CB7KF-BWN84-R7R2Y-793K2-8XDDG'
    }

    It 'Returns Unknown for unrecognised OS' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows XP Professional' } }
        Get-KMSKey -CimSession $null | Should -Be 'Unknown'
    }

    It 'Enterprise N LTSC does not match plain Enterprise N pattern' {
        Mock Get-CimInstance { [PSCustomObject]@{ Caption = 'Microsoft Windows 11 Enterprise N LTSC 2024' } }
        $key = Get-KMSKey -CimSession $null
        $key | Should -Be '92NFX-8DJQP-P6BBQ-THF9C-7CG2H'
        $key | Should -Not -Be 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4'
    }
}
