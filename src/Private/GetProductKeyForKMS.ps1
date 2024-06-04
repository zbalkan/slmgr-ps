# KMS Client License Keys - https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys
# Update as needed
function getProductKeyForKMS
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $OsVersion = ((Get-CimInstance -CimSession $CimSession -Class Win32_OperatingSystem).Caption)

    $productKey = switch -Wildcard ($OsVersion)
    {
        # End of support: Oct 13, 2026
        'Microsoft Windows Server 2022 Standard*' { 'VDYBN-27WPP-V4HQT-9VMD4-VMK7H' }
        'Microsoft Windows Server 2022 Datacenter*' { 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33' }

        # End of support: Jan 9, 2024
        'Microsoft Windows Server 2019 Standard*' { 'N69G4-B89J2-4G8F4-WWYCC-J464C' }
        'Microsoft Windows Server 2019 Datacenter*' { 'WMDGN-G9PQG-XVVXX-R3X43-63DFG' }
        'Microsoft Windows Server 2019 Essentials*' { 'WVDHN-86M7X-466P6-VHXV7-YY726' }

        # End of support: Oct 8, 2024 for 22H2
        'Microsoft Windows 11 Enterprise N' { 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4' }
        'Microsoft Windows 11 Enterprise' { 'NPPR9-FWDCX-D2C8J-H872K-2YT43' }
        'Microsoft Windows 11 Pro for Workstations' { 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J' }
        'Microsoft Windows 11 Pro for Workstations N' { '9FNHH-K3HBT-3W4TD-6383H-6XYWF' }
        'Microsoft Windows 11 Pro N' { 'MH37W-N47XK-V7XM9-C7227-GCQG9' }
        'Microsoft Windows 11 Pro' { 'W269N-WFGWX-YVC9B-4J6C9-T83GX' }

        # End of support: Oct 14, 2025
        'Microsoft Windows 10 Enterprise N' { 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4' }
        'Microsoft Windows 10 Enterprise' { 'NPPR9-FWDCX-D2C8J-H872K-2YT43' }
        'Microsoft Windows 10 Pro for Workstations' { 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J' }
        'Microsoft Windows 10 Pro for Workstations N' { '9FNHH-K3HBT-3W4TD-6383H-6XYWF' }
        'Microsoft Windows 10 Pro N' { 'MH37W-N47XK-V7XM9-C7227-GCQG9' }
        'Microsoft Windows 10 Pro' { 'W269N-WFGWX-YVC9B-4J6C9-T83GX' }

        default { 'Unknown' }
    }

    return $productKey
}
