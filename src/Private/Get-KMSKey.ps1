# KMS Client License Keys - https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys
# Update as needed
function Get-KMSKey
{
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $OsVersion = ((Get-CimInstance -CimSession $CimSession -Class Win32_OperatingSystem).Caption)

    $productKey = switch -Wildcard ($OsVersion)
    {
        # End of support: Oct 09, 2029
        'Microsoft Windows Server 2025 Standard*'                  { 'TVRH6-WHNXV-R9WG3-9XRFY-MY832'; break }
        'Microsoft Windows Server 2025 Datacenter: Azure Edition*' { 'XGN3F-F394H-FD2MY-PP6FD-8MCRC'; break }
        'Microsoft Windows Server 2025 Datacenter*'                { 'D764K-2NDRG-47T6Q-P8T8W-YP6DF'; break }

        # End of support: Oct 13, 2026
        'Microsoft Windows Server 2022 Standard*'                  { 'VDYBN-27WPP-V4HQT-9VMD4-VMK7H'; break }
        'Microsoft Windows Server 2022 Datacenter: Azure Edition*' { 'NTBV8-9K7Q8-V27C6-M2BTV-KHMXV'; break }
        'Microsoft Windows Server 2022 Datacenter*'                { 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33'; break }

        # End of support: Jan 9, 2029
        'Microsoft Windows Server 2019 Standard*'                  { 'N69G4-B89J2-4G8F4-WWYCC-J464C'; break }
        'Microsoft Windows Server 2019 Datacenter*'                { 'WMDGN-G9PQG-XVVXX-R3X43-63DFG'; break }
        'Microsoft Windows Server 2019 Essentials*'                { 'WVDHN-86M7X-466P6-VHXV7-YY726'; break }

        # End of support: Jan 12, 2027
        'Microsoft Windows Server 2016 Standard*'                  { 'WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY'; break }
        'Microsoft Windows Server 2016 Datacenter*'                { 'CB7KF-BWN84-R7R2Y-793K2-8XDDG'; break }
        'Microsoft Windows Server 2016 Essentials*'                { 'JCKRF-N37P4-C2D82-9YXRT-4M63B'; break }

        # More specific patterns must appear before general ones so the first match with break wins.
        # Windows 11 - End of support: Oct 2024 for 22H2; LTSC 2024 supported until Oct 2034
        'Microsoft Windows 11 Enterprise LTSC*'                    { 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'; break }
        'Microsoft Windows 11 Enterprise N LTSC*'                  { '92NFX-8DJQP-P6BBQ-THF9C-7CG2H'; break }
        'Microsoft Windows 11 Enterprise N*'                       { 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4'; break }
        'Microsoft Windows 11 Enterprise*'                         { 'NPPR9-FWDCX-D2C8J-H872K-2YT43'; break }
        'Microsoft Windows 11 Education N*'                        { '2WH4N-8QGBV-H22JP-CT43Q-MDWWJ'; break }
        'Microsoft Windows 11 Education*'                          { 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'; break }
        'Microsoft Windows 11 Pro for Workstations N*'             { '9FNHH-K3HBT-3W4TD-6383H-6XYWF'; break }
        'Microsoft Windows 11 Pro for Workstations*'               { 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J'; break }
        'Microsoft Windows 11 Pro Education N*'                    { 'YVWGF-BXNMC-HTQYQ-CPQ99-66QFC'; break }
        'Microsoft Windows 11 Pro Education*'                      { '6TP4R-GNPTD-KYYHQ-7B7DP-J447Y'; break }
        'Microsoft Windows 11 Pro N*'                              { 'MH37W-N47XK-V7XM9-C7227-GCQG9'; break }
        'Microsoft Windows 11 Pro*'                                { 'W269N-WFGWX-YVC9B-4J6C9-T83GX'; break }

        # Windows 10 - End of support: Oct 2025 for 22H2; LTSC 2021 supported until Jan 2027
        'Microsoft Windows 10 Enterprise LTSC*'                    { 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'; break }
        'Microsoft Windows 10 Enterprise N LTSC*'                  { '92NFX-8DJQP-P6BBQ-THF9C-7CG2H'; break }
        'Microsoft Windows 10 Enterprise N*'                       { 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4'; break }
        'Microsoft Windows 10 Enterprise*'                         { 'NPPR9-FWDCX-D2C8J-H872K-2YT43'; break }
        'Microsoft Windows 10 Education N*'                        { '2WH4N-8QGBV-H22JP-CT43Q-MDWWJ'; break }
        'Microsoft Windows 10 Education*'                          { 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'; break }
        'Microsoft Windows 10 Pro for Workstations N*'             { '9FNHH-K3HBT-3W4TD-6383H-6XYWF'; break }
        'Microsoft Windows 10 Pro for Workstations*'               { 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J'; break }
        'Microsoft Windows 10 Pro Education N*'                    { 'YVWGF-BXNMC-HTQYQ-CPQ99-66QFC'; break }
        'Microsoft Windows 10 Pro Education*'                      { '6TP4R-GNPTD-KYYHQ-7B7DP-J447Y'; break }
        'Microsoft Windows 10 Pro N*'                              { 'MH37W-N47XK-V7XM9-C7227-GCQG9'; break }
        'Microsoft Windows 10 Pro*'                                { 'W269N-WFGWX-YVC9B-4J6C9-T83GX'; break }

        default { 'Unknown' }
    }

    return $productKey
}
