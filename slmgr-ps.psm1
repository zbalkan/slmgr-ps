#Requires -RunAsAdministrator
#Requires -Version 5

# Implement your module commands in this script.


# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
Export-ModuleMember -Function Start-WindowsActivation


<#
.Synopsis
Activates Windows via KMS
.DESCRIPTION
A drop in replacement for slmgr script
.EXAMPLE
Start-WindowsActivation -Verbose # Activates the local computer
.EXAMPLE
Start-WindowsActivation -Computer WS01 # Activates the computer named WS01

.EXAMPLE
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500 # Activates the computer named WS01 against server.domain.net:2500
#>
function global:Start-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'default')]
    Param
    (
        # Type localhost or . for local computer or do not use the parameter
        [Parameter(Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [string[]]
        $Computers = @('localhost'),

        [Parameter(Mandatory = $false,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'SpecifyKMSServer')]
        [ValidateLength(6, 253)]
        [ValidateScript(
            {
                $pattern = [Regex]::new('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)')
                if ($pattern.Matches($_).Count -gt 0)
                {
                    $true
                }
                else
                {
                    throw "$_ is invalid. Please provide a valid FQDN"
                }
            })]
        [ValidateNotNullOrEmpty()]
        [string]
        $KMSServerFQDN,

        [Parameter(Mandatory = $false,
            Position = 2,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'SpecifyKMSServer')]
        [ValidateRange(1, 65535)]
        [int]
        $KMSServerPort = 1688
    )
    Begin
    {
        # Enum for a meaningful check. Reference: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct
        enum LicenseStatusCode
        {
            Unlicensed
            Licensed
            OOBGrace
            OOTGrace
            NonGenuineGrace
            Notification
            ExtendedGrace
        }

        function getLicenseStatus
        {
            param(
                [string]$Computer
            )
            if ($Computer -eq 'localhost')
            {
                $product = Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingProduct' | Where-Object { $_.PartialProductKey }
            }
            else
            {
                $product = Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingProduct' -ComputerName $Computer | Where-Object { $_.PartialProductKey }
            }
            $status = [LicenseStatusCode]( $product | Select-Object LicenseStatus).LicenseStatus
            $activated = $status -eq [LicenseStatusCode]::Licensed
            $result = [PSCustomObject]@{
                LicenseStatus = $status
                Activated     = $activated
            }
            return $result
        }

        function sanitizeComputerName
        {
            param(
                [string]$Computer
            )
            if ($Computer -eq '.' -or $Computer -eq '127.0.0.1' -or $null -eq $Computer)
            {
                return 'localhost'
            }
            else
            {
                return $Computer
            }
        }

        # KMS Client License Keys - https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys
        # Add as you wish
        function getProductKey
        {
            param(
                [string]$Computer
            )
            if ($Computer -eq 'localhost')
            {
                $OsVersion = ((Get-CimInstance -Class Win32_OperatingSystem).Caption)
            }
            else
            {
                $OsVersion = ((Get-CimInstance -Class Win32_OperatingSystem -ComputerName $Computer).Caption)
            }

            $productKey = switch -Wildcard ($OsVersion)
            {
                'Microsoft Windows Server 2022 Standard*' { 'VDYBN-27WPP-V4HQT-9VMD4-VMK7H' } # End of support: Oct 13, 2026
                'Microsoft Windows Server 2022 Datacenter*' { 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33' } # End of support: Oct 13, 2026
                'Microsoft Windows Server 2019 Standard*' { 'N69G4-B89J2-4G8F4-WWYCC-J464C' } # End of support: Jan 9, 2024
                'Microsoft Windows Server 2019 Datacenter*' { 'WMDGN-G9PQG-XVVXX-R3X43-63DFG' } # End of support: Jan 9, 2024
                'Microsoft Windows Server 2019 Essentials*' { 'WVDHN-86M7X-466P6-VHXV7-YY726' } # End of support: Jan 9, 2024
                # "Microsoft Windows Server 2016 Standard*"       { "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY" } # End of support: Jan 11, 2022
                # "Microsoft Windows Server 2016 Datacenter*"     { "CB7KF-BWN84-R7R2Y-793K2-8XDDG" } # End of support: Jan 11, 2022
                # "Microsoft Windows Server 2016 Essentials*"  	  { "JCKRF-N37P4-C2D82-9YXRT-4M63B" } # End of support: Jan 11, 2022
                # "Microsoft Windows Server 2012 R2 Datacenter*"  { "W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9" } # End of support: Oct 9, 2018
                # "Microsoft Windows Server 2012 R2 Standard*"    { "D2N9P-3P6X9-2R39C-7RTCD-MDVJX" } # End of support: Oct 9, 2018
                # "Microsoft Windows Server 2012 Standard*"       { "D2N9P-3P6X9-2R39C-7RTCD-MDVJX" } # End of support: October 9, 2018
                # "Microsoft Windows Server 2008 R2 Enterprise*"  { "489J6-VHDMP-X63PK-3K798-CPX3Y" } # End of support: Jan 14, 2020

                'Microsoft Windows 10 Enterprise*' { 'NPPR9-FWDCX-D2C8J-H872K-2YT43' } # End of support: Oct 14, 2025
                # 'Windows 10 Enterprise N*'                      { 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4' } # End of support: Oct 14, 2025
                'Microsoft Windows 10 Professional*' { 'W269N-WFGWX-YVC9B-4J6C9-T83GX' } # End of support: Oct 14, 2025
                # 'Windows 10 Professional N'                     { 'MH37W-N47XK-V7XM9-C7227-GCQG9' } # End of support: Oct 14, 2025
                # "Microsoft Windows 7 Enterprise*"               { "33PXH-7Y6KF-2VJC9-XBBR8-HVTHH" } # End of support: Jan 14, 2020
                # "Microsoft Windows 7 Professional*"             { "FJ82H-XT6CR-J8D7P-XQJJ2-GPDD4" } # End of support: Jan 14, 2020
                default { 'Unknown' }
            }

            return $productKey
        }

        function activateWithDNS
        {
            param(
                [string]$Computer,
                [string]$ProductKey
            )
            if ($Computer -eq 'localhost')
            {
                $service = Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingService'
            }
            else
            {
                $service = Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingService' -ComputerName $Computer
            }

            $service.InstallProductKey($ProductKey) > $null
            Start-Sleep -Seconds 10 # Installing product key takes time.
            $service.RefreshLicenseStatus() > $null
            Start-Sleep -Seconds 2 # It also takes time.
        }

        function activateWithParams
        {
            param(
                [string]$Computer,
                [string]$ProductKey,
                [string]$KeyServerName,
                [int]$KeyServerPort
            )
            if ($Computer -eq 'localhost')
            {
                $service = Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingService'
            }
            else
            {
                $service = Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingService' -ComputerName $Computer
            }

            $service.SetKeyManagementServiceMachine($KeyServerName)
            $service.SetKeyManagementServicePort($KeyServerPort)

            $service.InstallProductKey($ProductKey) > $null
            Start-Sleep -Seconds 10 # Installing product key takes time.
            $service.RefreshLicenseStatus() > $null
            Start-Sleep -Seconds 2 # It also takes time.
        }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess('Computer', 'Activate license via KMS'))
        {
            $ErrorActionPreference = 'Stop'
            Write-Verbose 'ErrorActionPreference: Stop'

            Write-Verbose "Enumerating computers: $($Computers.Count) computer(s)."
            foreach ($Computer in $Computers)
            {

                # Sanitize Computer name
                $Computer = sanitizeComputerName -Computer $Computer
                Write-Verbose "Computer name: $Computer"

                # Check Windows Activation Status
                $product = getLicenseStatus -Computer $Computer
                Write-Verbose "License Status: $($product.Status)"
                if ($product.Activated) { Write-Warning 'The product is already activated.'; continue; }

                # Get product key
                $productKey = getProductKey -Computer $Computer
                Write-Verbose "Product Key (for KMS): $productKey"

                # Activate Windows
                if ($productKey -eq 'Unknown')
                {
                    Write-Error 'Unknown OS.'
                }
                else
                {
                    if ($PSCmdlet.ParameterSetName -eq 'SpecifyKMSServer')
                    {
                        activateWithParams -Computer $Computer -ProductKey $productKey -KeyServerName $KMSServerFQDN -KeyServerPort $KMSServerPort
                    }
                    else
                    {
                        activateWithDNS -Computer $Computer -ProductKey $productKey
                    }

                    $product = getLicenseStatus -Computer $Computer
                    if ($product.Activated)
                    {
                        Write-Verbose "The computer activated succesfully. Current status: $($product.LicenseStatus)"
                    }
                    else
                    {
                        Write-Error "Activation failed. Current status: $($product.LicenseStatus)"
                    }
                }
            }
        }
    }
}
