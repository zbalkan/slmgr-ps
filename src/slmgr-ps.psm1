#Requires -RunAsAdministrator
#Requires -Version 5

# Implement your module commands in this script.


# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
Export-ModuleMember -Cmdlet *-*

<#
.Synopsis
Activates Windows via KMS
.DESCRIPTION
A drop in replacement for slmgr script
.INPUTS
string[]. You can pass the computer names
.OUTPUTS
None if successful. Error message if there is an error.
.EXAMPLE
Start-WindowsActivation -Verbose # Activates the local computer
.EXAMPLE
Start-WindowsActivation -Computer WS01 -Credentials (Get-Credential) # Activates the computer named WS01 using different credentials
.EXAMPLE
Start-WindowsActivation -Computer WS01, WS02 -CacheEnabled $false # Disabled the KMS cache for the computers named WS01 and WS02. Cache is enabled by default.
.EXAMPLE
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500 # Activates the computer named WS01 against server.domain.net:2500
.EXAMPLE
Start-WindowsActivation -ReArm # ReArm the trial period. ReArming already licensed devices can break current license issues. Guard clauses wil protect 99% but cannot guarantee 100%.
.EXAMPLE
Start-WindowsActivation -Offline -ConfirmationID <confirmation ID> # Used for offline -aka phone- activation
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function global:Start-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'Activate')]
    Param
    (
        # Type localhost or . for local computer or do not use the parameter
        [Parameter(Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Activate')]
        [Parameter(ParameterSetName = 'SpecifyKMSServer')]
        [Parameter(ParameterSetName = 'Rearm')]
        [Parameter(ParameterSetName = 'Cache')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [string[]]
        $Computers = @('localhost'),

        # Define credentials other than current user if needed
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Activate')]
        [Parameter(ParameterSetName = 'SpecifyKMSServer')]
        [Parameter(ParameterSetName = 'Rearm')]
        [Parameter(ParameterSetName = 'Cache')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [PSCredential]
        $Credentials = $null,

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
        $KMSServerPort = 1688,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Rearm')]
        [switch]
        $Rearm,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Cache')]
        [bool]
        $CacheEnabled,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Offline')]
        [switch]$Offline,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Offline')]
        [ValidateLength(64, 64)]
        [ValidateScript(
            {
                $pattern = [Regex]::new('^[0-9]{64}$')
                if ($pattern.Matches($_).Count -gt 0)
                {
                    $true
                }
                else
                {
                    throw "$_ is invalid. Please provide a valid Confirmation Id"
                }
            })]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfirmationId

    )
    Begin
    {
        $PreviousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        Write-Verbose 'ErrorActionPreference: Stop'
    }
    Process
    {
        if ($pscmdlet.ShouldProcess($Computers -join ', ', 'Activate license via KMS'))
        {
            # Sanitize Computer names
            $Computers = sanitizeComputerName -Computers $Computers

            Write-Verbose "Creating new CimSession for computer(s) $($Computers -join ', ')"
            $session = getSession -Credentials $Credentials -Computers $Computers

            Write-Verbose "Enumerating computers: $($Computers.Count) computer(s)."
            foreach ($Computer in $Computers)
            {
                Write-Verbose "Computer name: $Computer"

                if ($PSCmdlet.ParameterSetName -eq 'Offline')
                {
                    try
                    {
                        Write-Verbose 'Initiating offline activation operation'
                        activateOffline -ConfirmationId $ConfirmationId -Computer $Computer -Session $session
                        exit 0
                    }
                    catch
                    {
                        exit 1
                    }

                }

                # Rearm can be run on trial versions only.
                # Try rearm and exit early.
                if ($PSCmdlet.ParameterSetName -eq 'Rearm')
                {
                    try
                    {
                        Write-Verbose 'Initiating ReArm operation'
                        rearm -Computer $Computer -Session $session
                        exit 0
                    }
                    catch
                    {
                        exit 1
                    }
                }

                # No rearm, continue with activating.

                # Set KMS cache preference
                if ($PSCmdlet.ParameterSetName -eq 'Cache')
                {
                    try
                    {
                        Write-Verbose "Changing KMS cache setting as: $CacheEnabled"
                        manageCache -Computer $Computer -Enabled $CacheEnabled -Session $session
                        exit 0
                    }
                    catch
                    {
                        exit 1
                    }
                }

                # Activation
                Write-Verbose 'Initiating Activation operation'
                activate -Computer $Computer -KMSServerFQDN $KMSServerFQDN -KMSServerPort $KMSServerPort -Session $session
            }
        }
    }
    End
    {
        $ErrorActionPreference = $PreviousPreference
        if ($null -ne $session)
        {
            Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
        }
    }
}


<#
.Synopsis
Collects Windows license information
.DESCRIPTION
A drop in replacement for slmgr script /dli and /dlv options
.INPUTS
string[]. You can pass the computer names
.OUTPUTS
psobject. The number of properties depends on basic or extended mode.
.EXAMPLE
Get-WindowsActivation # Collects basic license information of local computer, equal to slmgr.vbs /dli
.EXAMPLE
Get-WindowsActivation -Extended # Collects extended license information of local computer, equal to slmgr.vbs /dlv
.EXAMPLE
Get-WindowsActivation -Expiry # Collects license expiration information of local computer, equal to slmgr.vbs /xpr
.EXAMPLE
Get-WindowsActivation -Computer WS01 # Collects basic license information of computer WS01 over WinRM
.EXAMPLE
Get-WindowsActivation -Computer WS01 -Credentials (Get-Credential) # Collects basic license information of computer WS01 over WinRM using different credentials
.EXAMPLE
Get-WindowsActivation -Offline # Get the offline installation ID for offline -aka phone- activation
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function global:Get-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $true,
        ConfirmImpact = 'Low',
        DefaultParameterSetName = 'Basic')]
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'Extended')]
        [Parameter(ParameterSetName = 'Expiry')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [string[]]
        $Computers = @('localhost'),

        # Define credentials other than current user if needed
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'Extended')]
        [Parameter(ParameterSetName = 'Expiry')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [PSCredential]
        $Credentials = $null,

        [Parameter(Mandatory = $false, ParameterSetName = 'Extended')]
        [switch]$Extended,

        [Parameter(Mandatory = $false, ParameterSetName = 'Expiry')]
        [switch]$Expiry,

        [Parameter(ParameterSetName = 'Offline')]
        [switch]$Offline
    )
    Begin
    {
    }
    Process
    {
        if ($pscmdlet.ShouldProcess($Computers -join ', ', 'Collect license information'))
        {
            # Sanitize Computer names
            $Computers = sanitizeComputerName -Computers $Computers

            Write-Verbose "Creating new CimSession for computer(s) $($Computers -join ', ')"
            $session = getSession -Credentials $Credentials -Computers $Computers

            Write-Verbose "Enumerating computers: $($Computers.Count) computer(s)."
            foreach ($Computer in $Computers)
            {
                if ($Extended.IsPresent)
                {
                    return getExtendedLicenseInformation -Computer $Computer -Session $session
                }
                if ($Expiry.IsPresent)
                {
                    return getExpiryInformation -Computer $Computer -Session $session
                }
                if ($Offline.IsPresent)
                {
                    return getInstallationId -Computer $Computer -Session $session
                }
                else
                {
                    return getBasicLicenseInformation -Computer $Computer -Session $session
                }
            }
        }
    }
    End
    {
        if ($null -ne $session)
        {
            Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
        }
    }
}


#region Private functions

#region Data structures
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
#endregion Data structures

#region Activation functions

function activate
{
    [CmdletBinding()]
    param(
        [string[]]$Computer,
        [string]$KMSServerFQDN,
        [int]$KMSServerPort,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    # Check Windows Activation Status
    $product = getLicenseStatus -Computer $Computer -Session $Session
    Write-Verbose "License Status: $($product.Status)"
    if ($product.Activated) { Write-Warning 'The product is already activated.'; return; }

    # Get product key
    $productKey = getProductKey -Computer $Computer -Session $Session
    Write-Verbose "Product Key (for KMS): $productKey"

    # Activate Windows
    if ($productKey -eq 'Unknown')
    {
        throw 'Unknown OS.'
    }
    else
    {
        if ($PSCmdlet.ParameterSetName -eq 'SpecifyKMSServer')
        {
            activateWithParams -Computer $Computer -ProductKey $productKey -KeyServerName $KMSServerFQDN -KeyServerPort $KMSServerPort -Session $Session
        }
        else
        {
            activateWithDNS -Computer $Computer -ProductKey $productKey -Session $Session
        }

        $product = getLicenseStatus -Computer $Computer -Session $Session
        if ($product.Activated)
        {
            Write-Verbose "The computer activated succesfully. Current status: $($product.LicenseStatus)"
        }
        else
        {
            throw "Activation failed. Current status: $($product.LicenseStatus)"
        }
    }
}

function activateWithDNS
{
    [CmdletBinding()]
    param(
        [string]$Computer,
        [string]$ProductKey,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )
    if ($Computer -eq 'localhost')
    {
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -CimSession $Session | cimToWmi
    }
    else
    {
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -ComputerName $Computer -CimSession $Session | cimToWmi
    }

    [void]$service.InstallProductKey($ProductKey)
    Start-Sleep -Seconds 10 # Installing product key takes time.
    [void]$service.RefreshLicenseStatus()
    Start-Sleep -Seconds 2 # It also takes time.
}

function activateWithParams
{
    param(
        [string]$Computer,
        [string]$ProductKey,
        [string]$KeyServerName,
        [int]$KeyServerPort,
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )
    if ($Computer -eq 'localhost')
    {
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -CimSession $Session | cimToWmi
    }
    else
    {
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -ComputerName $Computer -CimSession $Session | cimToWmi
    }

    $service.SetKeyManagementServiceMachine($KeyServerName)
    $service.SetKeyManagementServicePort($KeyServerPort)

    [void]$service.InstallProductKey($ProductKey)
    Start-Sleep -Seconds 10 # Installing product key takes time.
    [void]$service.RefreshLicenseStatus()
    Start-Sleep -Seconds 2 # It also takes time.
}

function activateOffline
{
    [CmdletBinding()]
    [CmdletBinding()]
    param (
        [string]
        $ConfirmationId,
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    $query = "SELECT Version
    FROM SoftwareLicensingProduct
    WHERE PartialProductKey <> null AND Name LIKE 'Win%'"

    if ($Computer -like 'localhost')
    {
        Write-Verbose 'Connecting to local computer...'
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -CimSession $Session | cimToWmi
        $product = Get-CimInstance -Verbose:$false -Query $query -CimSession $Session | cimToWmi
    }
    else
    {
        Write-Verbose 'Connecting to remote computer...'
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -ComputerName $Computer -CimSession $Session | cimToWmi
        $product = Get-CimInstance -Verbose:$false -Query $query -ComputerName $Computer -CimSession $Session | cimToWmi
    }

    $InstallationId = getInstallationId -Computer $Computer -CimSession $Session
    Write-Verbose 'Submitting activation and confirmation IDs...'
    Write-Debug 'Offline Installation ID: $InstallationId'
    Write-Debug 'Confirmation ID: $ConfirmationId'

    if ([int]$product.DepositOfflineConfirmationId($InstallationId, $ConfirmationId) -ne 0)
    {
        throw 'Failed to activate with offline activation. Check the Confirmation ID.'
    }
    Write-Verbose 'Updating the license status...'
    [void]$service.RefreshLicenseStatus()
    [void]$product.refresh_ # Not sure if it is an undocumented internal command. I have found this gem in slgr.vbs
}

function rearm
{
    [CmdletBinding()]
    param(
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    if ($Computer -like 'localhost')
    {
        Write-Verbose 'Connecting to local computer'
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -CimSession $Session | cimToWmi
    }
    else
    {
        Write-Verbose 'Connecting to remote computer'
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -ComputerName $Computer -CimSession $Session | cimToWmi
    }

    $isRearmable = canRearm -Computer $Computer -Session $Session
    Write-Verbose "Is rearmable: $isRearmable"

    if ($isRearmable -eq $false)
    {
        Write-Verbose 'No need to rearm.'
        continue
    }

    if ($product.LicenseStatus -eq [LicenseStatusCode]::Unknown)
    {
        throw 'License status cannot be collected. It is suggested to restart computer.'
    }

    try
    {
        if ($service.ReArmWindows() -ne 0)
        {
            throw 'Failed to rearm Windows.'
        }
        [void]$service.RefreshLicenseStatus()
        Write-Verbose 'Command completed successfully.'
        Write-Verbose 'Please restart the system for the changes to take effect.'
    }
    catch [System.Management.Automation.MethodInvocationException]
    {
        throw 'Rearm failed.'
    }
}

function canRearm
{
    [CmdletBinding()]
    param(
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    $status = (getLicenseStatus -Computer $Computer -Session $Session).LicenseStatus

    # Any status exvept Licensed and Notification
    $rearmableStatuses = @([LicenseStatusCode]::Unlicensed,
        [LicenseStatusCode]::OOBGrace,
        [LicenseStatusCode]::OOTGrace,
        [LicenseStatusCode]::NonGenuineGrace,
        [LicenseStatusCode]::ExtendedGrace)

    Write-Verbose "Current license status: $status"
    return ($status -in $rearmableStatuses)
}

function manageCache
{
    param(
        [string]$Computer,
        [bool]$Enabled,
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )
    if ($Computer -eq 'localhost')
    {
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -CimSession $Session | cimToWmi
    }
    else
    {
        $service = Get-CimInstance -Verbose:$false -ClassName SoftwareLicensingService -ComputerName $Computer -CimSession $Session | cimToWmi
    }

    if ($Enabled)
    {
        $service.DisableKeyManagementServiceHostCaching(0) > $null # Disable caching
    }
    else
    {
        $service.DisableKeyManagementServiceHostCaching(1) > $null # Disable caching
    }

}

#endregion Activation functions

#region Information functions

# KMS Client License Keys - https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys
# Add as you wish
function getProductKey
{
    [CmdletBinding()]
    param(
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )
    if ($Computer -eq 'localhost')
    {
        $OsVersion = ((Get-CimInstance -Verbose:$false -Class Win32_OperatingSystem -CimSession $Session).Caption)
    }
    else
    {
        $OsVersion = ((Get-CimInstance -Verbose:$false -Class Win32_OperatingSystem -ComputerName $Computer -CimSession $Session).Caption)
    }

    $productKey = switch -Wildcard ($OsVersion)
    {
        # End of support: Oct 13, 2026
        'Microsoft Windows Server 2022 Standard*' { 'VDYBN-27WPP-V4HQT-9VMD4-VMK7H' }
        'Microsoft Windows Server 2022 Datacenter*' { 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33' } # End of support: Oct 13, 2026

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
        'Microsoft Windows 10 Enterprise N' { 'DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4' } # End of support: Oct 14, 2025
        'Microsoft Windows 10 Enterprise' { 'NPPR9-FWDCX-D2C8J-H872K-2YT43' } # End of support: Oct 14, 2025
        'Microsoft Windows 10 Pro for Workstations' { 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J' } # End of support: Oct 14, 2025
        'Microsoft Windows 10 Pro for Workstations N' { '9FNHH-K3HBT-3W4TD-6383H-6XYWF' } # End of support: Oct 14, 2025
        'Microsoft Windows 10 Pro N' { 'MH37W-N47XK-V7XM9-C7227-GCQG9' } # End of support: Oct 14, 2025
        'Microsoft Windows 10 Pro' { 'W269N-WFGWX-YVC9B-4J6C9-T83GX' } # End of support: Oct 14, 2025

        default { 'Unknown' }
    }

    return $productKey
}

function getLicenseStatus
{
    [CmdletBinding()]
    param(
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    $query = 'SELECT LicenseStatus
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Verbose:$false -Query $query -CimSession $Session
    }
    else
    {
        $product = Get-CimInstance -Verbose:$false -Query $query -ComputerName $Computer -CimSession $Session
    }
    $status = [LicenseStatusCode]( $product | Select-Object LicenseStatus).LicenseStatus
    $activated = $status -eq [LicenseStatusCode]::Licensed
    $result = [PSCustomObject]@{
        'License Status' = $status
        Activated        = $activated
    }
    return $result
}

function getBasicLicenseInformation
{
    [CmdletBinding()]
    param (
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    $query = 'SELECT Name,Description,PartialProductKey,LicenseStatus
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Verbose:$false -Query $query -CimSession $Session
    }
    else
    {
        $product = Get-CimInstance -Verbose:$false -Query $query -ComputerName $Computer -CimSession $Session
    }
    $name = $product.Name
    $desc = $product.Description
    $partial = $product.PartialProductKey
    $status = [LicenseStatusCode]($product.LicenseStatus)

    $result = [PSCustomObject]@{
        Name                  = $name
        Description           = $desc
        'Partial Product Key' = $partial
        'License Status'      = $status
    }
    return $result
}

function getExtendedLicenseInformation
{
    [CmdletBinding()]
    param (
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    $extendedQuery = 'SELECT Name,Description,ID,ApplicationID,ProductKeyID,ProductKeyChannel,OfflineInstallationId,UseLicenseURL,ValidationURL,PartialProductKey,LicenseStatus,RemainingAppReArmCount,RemainingSkuReArmCount,TrustedTime
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Verbose:$false -Query $extendedQuery -CimSession $Session
    }
    else
    {
        $product = Get-CimInstance -Verbose:$false -Query $extendedQuery -ComputerName $Computer -CimSession $Session
    }
    $name = $product.Name
    $desc = $product.Description
    $activationID = $product.ID
    $applicationID = $product.ApplicationID
    $pkID = $product.ProductKeyID
    $pkChannel = $product.ProductKeyChannel
    $installationID = $product.OfflineInstallationId
    $licenseUrl = $product.UseLicenseURL
    $validationUrl = $product.ValidationURL
    $partial = $product.PartialProductKey
    $status = [LicenseStatusCode]( $product.LicenseStatus)
    $remainingAppRearm = $product.RemainingAppReArmCount
    $remainingSkuRearm = $product.RemainingSkuReArmCount
    $trustedTime = ''
    if ([string]::IsNullOrEmpty($product.Trustedtime) -eq $false)
    {
        $trustedTime = [datetime]::Parse($product.Trustedtime)
    }

    $result = [PSCustomObject]@{
        Name                            = $name
        Description                     = $desc
        'Activation ID'                 = $activationID
        'Application ID'                = $applicationID
        'Extended PID'                  = $pkID
        'Product Key Channel'           = $pkChannel
        'Installation ID'               = $installationID
        'Use License URL'               = $licenseUrl
        'Validation URL'                = $validationUrl
        'Partial Product Key'           = $partial
        'License Status'                = $status
        'Remaining Windows Rearm Count' = $remainingAppRearm
        'Remaining SKU Rearm Count'     = $remainingSkuRearm
        'Trusted Time'                  = $trustedTime
    }
    return $result
}

function getExpiryInformation
{
    [CmdletBinding()]
    param (
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    $expiryQuery = 'SELECT ID, ApplicationId, PartialProductKey, LicenseIsAddon, Description, Name, LicenseStatus, GracePeriodRemaining
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Verbose:$false -Query $expiryQuery -CimSession $Session
    }
    else
    {
        $product = Get-CimInstance -Verbose:$false -Query $expiryQuery -ComputerName $Computer -CimSession $Session
    }
    $name = $product.Name
    $status = [LicenseStatusCode]($product.LicenseStatus)
    $graceRemaining = $product.GracePeriodRemaining
    $endDate = (Get-Date).AddMinutes($graceRemaining)

    $expirationInfo = switch ($product.LicenseStatus)
    {
        0 { [LicenseStatusCode]::Unlicensed.ToString() }
        1
        {
            if ($graceRemaining -eq 0)
            {
                'The machine is permanently activated.'
            }
            else
            {
                if ($product.Description -icontains 'TIMEBASED_')
                {
                    "Timebased activation will expire $endDate"
                }
                elif($product.Description -icontains 'VIRTUAL_MACHINE_ACTIVATION') {
                    "Automatic VM activation will expire $endDate"
                }
                else {
                    "Volume activation will expire $endDate"
                }
            }
        }
        2 { "Initial grace period ends $endDate" }
        3 { "Additional grace period ends $endDate" }
        4 { "Non-genuine grace period ends $endDate" }
        5 { 'Windows is in Notification mode' }
        6 { "Extended grace period ends $endDate" }
        Default
        {
            throw 'Unexpected license status'
        }
    }

    $result = [PSCustomObject]@{
        Name                     = $name
        'License Status'         = $status
        'Expiration Information' = $expirationInfo
    }
    return $result
}

function getInstallationId
{
    [CmdletBinding()]
    param (
        [string]$Computer,
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimSession]$Session
    )

    $query = 'SELECT OfflineInstallationId, PartialProductKey
    FROM SoftwareLicensingProduct
    WHERE PartialProductKey <> null AND Name LIKE "Windows%"'

    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Verbose:$false -Query $query -CimSession $Session
    }
    else
    {
        $product = Get-CimInstance -Verbose:$false -Query $query -ComputerName $Computer -CimSession $Session
    }

    $result = [PSCustomObject]@{
        'Offline Installation Id' = $product.OfflineInstallationId
    }
    return $result
}

#endregion Information functions

#region Utility functions

function sanitizeComputerName
{
    [CmdletBinding()]
    param(
        [string[]]$Computers
    )
    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($Computer in $Computers)
    {
        $Computer = $Computer.Trim()
        if ($Computer -eq '.' -or $Computer -eq '127.0.0.1' -or $null -eq $Computer)
        {
            return 'localhost'
        }
        else
        {
            $result += $Computer
        }
    }
    return $result
}

function getSession
{
    [CmdletBinding()]
    param (
        [AllowNull()]
        [PSCredential]
        $Credentials = $null,
        [string[]]
        $Computers
    )

    if ($Computers -eq @('localhost'))
    {
        if ($null -eq $Credentials)
        {
            Write-Verbose 'No credentials provided, using current session'
            $session = New-CimSession -Name 'SlmgrLocalSession'
        }
        else
        {
            Write-Verbose "Credentials provided for user $($Credentials.UserName). Creating new session."
            $session = New-CimSession -Name 'SlmgrLocalSession' -Credential $Credentials
        }
    }
    else
    {
        if ($null -eq $Credentials)
        {
            Write-Verbose 'No credentials provided, using current session'
            $session = New-CimSession -Name 'SlmgrRemoteSession' -ComputerName $Computers
        }
        else
        {
            Write-Verbose "Credentials provided for user $($Credentials.UserName). Creating new session."
            $session = New-CimSession -Name 'SlmgrRemoteSession' -Credential $Credentials -ComputerName $Computers
        }
    }
    return $session
}

# Reference: https://rohnspowershellblog.wordpress.com/2013/06/15/converting-a-ciminstance-to-a-managementobject-and-back/
function cimToWmi
{

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ciminstance] $InputObject
    )

    process
    {
        $Keys = $InputObject.CimClass.CimClassProperties |
        Where-Object { $_.Qualifiers.Name -contains 'Key' } |
        Select-Object Name, CimType |
        Sort-Object Name

        $KeyValuePairs = $Keys | ForEach-Object {

            $KeyName = $_.Name
            switch -regex ($_.CimType)
            {
                'Boolean|.Int\d+'
                {
                    # No quotes surrounding value:
                    $Value = $InputObject.$KeyName
                }

                'DateTime'
                {
                    # Conver to WMI datetime
                    $Value = '"{0}"' -f [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($InputObject.$KeyName)
                }

                'Reference'
                {
                    throw "CimInstance contains a key with type 'Reference'. This isn't currenlty supported (but can be added later)"
                }

                default
                {
                    # Treat it like a string and cross your fingers:
                    $Value = '"{0}"' -f ($InputObject.$KeyName -replace "`"", "\`"")
                }
            }
            '{0}={1}' -f $KeyName, $Value
        }

        if ($KeyValuePairs)
        {
            $KeyValuePairsString = '.{0}' -f ($KeyValuePairs -join ',')
        }
        else
        {
            # This is how WMI seems to handle paths with no keys
            $KeyValuePairsString = '=@'
        }

        return [wmi]('\\{0}\{1}:{2}{3}' -f $InputObject.CimSystemProperties.ServerName,
                               ($InputObject.CimSystemProperties.Namespace -replace '/', '\'),
            $InputObject.CimSystemProperties.ClassName,
            $KeyValuePairsString)
    }
}
#endregion Utility functions

#endregion Private functions
