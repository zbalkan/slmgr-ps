#Requires -RunAsAdministrator
#Requires -Version 5

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
Start-WindowsActivation -Computer WS01, WS02 -CacheDisabled $false # Disabled the KMS cache for the computers named WS01 and WS02. Cache is enabled by default.
.EXAMPLE
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500 # Activates the computer named WS01 against server.domain.net:2500
.EXAMPLE
Start-WindowsActivation -ReArm # ReArm the trial period. ReArming already licensed devices can break current license issues. Guard clauses wil protect 99% but cannot guarantee 100%.
.EXAMPLE
Start-WindowsActivation -Offline -ConfirmationID <confirmation ID> # Used for offline -aka phone- activation
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Start-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'ActivateWithKMS')]
    Param
    (
        # Type localhost or . for local computer or do not use the parameter
        [Parameter(Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'ActivateWithKMS')]
        [Parameter(ParameterSetName = 'Rearm')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [string[]]
        $Computer = @('localhost'),

        # Define credentials other than current user if needed
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'ActivateWithKMS')]
        [Parameter(ParameterSetName = 'Rearm')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [PSCredential]
        $Credentials,

        [Parameter(Mandatory = $false,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ActivateWithKMS')]
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
            ParameterSetName = 'ActivateWithKMS')]
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
            ParameterSetName = 'ActivateWithKMS')]
        [switch]
        $CacheDisabled,

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
        if ($pscmdlet.ShouldProcess($Computer -join ', ', 'Activate license via KMS'))
        {
            Write-Verbose "Enumerating computers: $($Computer.Count) computer(s)."
            foreach ($c in $Computer)
            {
                Write-Verbose "Creating new CimSession for computer $c"
                $session = getSession -Computer $c -Credentials $Credentials

                Write-Verbose 'Connecting to SoftwareLicensingService..'
                $service = getWMIObject -CimSession $session -ClassName SoftwareLicensingService

                try
                {
                    switch ($PSCmdlet.ParameterSetName)
                    {
                        'Offline'
                        {
                            Write-Verbose 'Initiating offline activation operation'
                            activateOffline -CimSession $session -Service $service -$ConfirmationId
                            exit 0
                        }

                        'Rearm'
                        {
                            Write-Verbose 'Initiating ReArm operation'
                            rearm -CimSession $session -Service $service
                            exit 0
                        }

                        'ActivateWithKMS'
                        {
                            Write-Verbose "Changing KMS cache setting as: $($CacheDisabled.IsPresent -eq $false)"
                            if ($CacheDisabled.IsPresent)
                            {
                                $service.DisableKeyManagementServiceHostCaching(1) > $null # Disable caching
                            }

                            Write-Verbose 'Initiating KMS activation operation'
                            activateWithKMS $PSBoundParameters -CimSession $session -Service $service
                            exit 0
                        }

                        default
                        {
                            throw 'Unknown parameter combination' # We do not expect this to be triggered at all but it is here to prevent human errors
                        }
                    }
                }
                catch
                {
                    exit 1
                }
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
function Get-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $true,
        ConfirmImpact = 'None',
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
        $Computer = @('localhost'),

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
        $Credentials,

        [Parameter(Mandatory = $false, ParameterSetName = 'Extended')]
        [switch]$Extended,

        [Parameter(Mandatory = $false, ParameterSetName = 'Expiry')]
        [switch]$Expiry,

        [Parameter(ParameterSetName = 'Offline')]
        [switch]$Offline
    )
    Begin
    {
        $PreviousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        Write-Verbose 'ErrorActionPreference: Stop'
    }
    Process
    {
        if ($pscmdlet.ShouldProcess($Computer -join ', ', 'Collect license information'))
        {
            Write-Verbose "Enumerating computers: $($Computer.Count) computer(s)."
            foreach ($c in $Computer)
            {
                Write-Verbose "Creating new CimSession for computer $c"
                $session = getSession -Computer $c -Credentials $Credentials

                switch ($PSCmdlet.ParameterSetName)
                {
                    'Extended'
                    {
                        return queryExtendedLicenseInformation -CimSession $session
                    }
                    'Expiry'
                    {
                        return queryExpiryInformation -CimSession $session
                    }
                    'Offline'
                    {
                        return queryOfflineInstallationId -CimSession $session
                    }
                    default
                    {
                        return queryBasicLicenseInformation -CimSession $session
                    }
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

function activateWithKMS
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [wmi]$Service,
        [string]$KMSServerFQDN,
        [int]$KMSServerPort
    )

    # Check Windows Activation Status
    $status = (queryLicenseStatus -CimSession $CimSession).LicenseStatus
    Write-Verbose "License Status: $($status)"
    if ($status.Activated) { Write-Warning 'The product is already activated.'; return; }

    # Get product key
    $productKey = getProductKeyForKMS -CimSession $CimSession
    Write-Verbose "Product Key (for KMS): $productKey"

    # Activate Windows
    if ($productKey -eq 'Unknown')
    {
        throw 'Unknown OS.'
    }
    else
    {
        # If provided, u[date values for Server FQDN and Port
        if ($PSBoundParameters.ContainsKey('KMSServerFQDN'))
        {
            $service.SetKeyManagementServiceMachine($KeyServerName)
        }
        if ($PSBoundParameters.ContainsKey('KeyServerPort'))
        {
            $service.SetKeyManagementServicePort($KeyServerPort)
        }

        [void]$service.InstallProductKey($ProductKey)
        Start-Sleep -Seconds 10 # Installing product key takes time.
        [void]$service.RefreshLicenseStatus()
        Start-Sleep -Seconds 2 # It also takes time.


        # Check Windows Activation Status
        $license = queryLicenseStatus -CimSession $CimSession

        if ($license.Activated)
        {
            Write-Verbose "The computer activated succesfully. Current status: $($license.LicenseStatus)"
        }
        else
        {
            throw "Activation failed. Current status: $($license.LicenseStatus)"
        }
    }
}

function activateOffline
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [string]$ConfirmationId,
        [wmi]$Service
    )

    # Check Windows Activation Status
    $status = (queryLicenseStatus -CimSession $CimSession).LicenseStatus
    Write-Verbose "License Status: $($status)"
    if ($status.Activated) { Write-Warning 'The product is already activated.'; return; }

    $query = "SELECT Version
    FROM SoftwareLicensingProduct
    WHERE PartialProductKey <> null AND Name LIKE 'Win%'"

    Write-Verbose 'Connecting to computer...'
    $product = getWMIObject -CimSession $CimSession -Query $query

    $InstallationId = (queryOfflineInstallationId -CimSession $CimSession).'Offline Installation Id'
    Write-Verbose 'Submitting activation and confirmation IDs...'
    Write-Debug 'Offline Installation ID: $InstallationId'
    Write-Debug 'Confirmation ID: $ConfirmationId'

    if ([int]$product.DepositOfflineConfirmationId($InstallationId, $ConfirmationId) -ne 0)
    {
        throw 'Failed to activate with offline activation. Check the Confirmation ID.'
    }
    Write-Verbose 'Updating the license status...'
    [void]$Service.RefreshLicenseStatus()
    [void]$product.refresh_ # Not sure if it is an undocumented internal command. I have found this gem in slmgr.vbs
}

function rearm
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [wmi]$Service
    )

    $status = (queryLicenseStatus -CimSession $CimSession).LicenseStatus
    if ($status -eq [LicenseStatusCode]::Unknown)
    {
        throw 'License status cannot be collected. It is suggested to restart computer.'
    }

    Write-Verbose "Current license status: $status"

    # Any status except Unknown, Licensed and Notification
    $rearmableStatuses = @([LicenseStatusCode]::Unlicensed,
        [LicenseStatusCode]::OOBGrace,
        [LicenseStatusCode]::OOTGrace,
        [LicenseStatusCode]::NonGenuineGrace,
        [LicenseStatusCode]::ExtendedGrace)
    $isRearmable = $status -in $rearmableStatuses
    Write-Verbose "Is rearmable: $isRearmable"

    if ($isRearmable -eq $false)
    {
        Write-Verbose 'No need to rearm.'
        return
    }

    try
    {
        if ($Service.ReArmWindows() -ne 0)
        {
            throw 'Failed to rearm Windows.'
        }
        [void]$Service.RefreshLicenseStatus()
        Write-Verbose 'Command completed successfully.'
        Write-Verbose 'Please restart the system for the changes to take effect.'
    }
    catch [System.Management.Automation.MethodInvocationException]
    {
        throw 'Rearm failed.'
    }
}

#endregion Activation functions

#region Information functions

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

function queryLicenseStatus
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT LicenseStatus
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = getWMIObject -CimSession $CimSession -Query $query

    $status = [LicenseStatusCode]( $product | Select-Object LicenseStatus).LicenseStatus
    $activated = $status -eq [LicenseStatusCode]::Licensed
    $result = [PSCustomObject]@{
        'License Status' = $status
        Activated        = $activated
    }
    return $result
}

function queryBasicLicenseInformation
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT ID,Name,Description,PartialProductKey,LicenseStatus
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = getWMIObject -CimSession $CimSession -Query $query

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

function queryExtendedLicenseInformation
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT Name,Description,ID,ApplicationID,ProductKeyID,ProductKeyChannel,OfflineInstallationId,UseLicenseURL,ValidationURL,PartialProductKey,LicenseStatus,RemainingAppReArmCount,RemainingSkuReArmCount,TrustedTime
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = getWMIObject -CimSession $CimSession -Query $query

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
    $trustedTime = [string]::Empty
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

function queryExpiryInformation
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT ID, ApplicationId, PartialProductKey, LicenseIsAddon, Description, Name, LicenseStatus, GracePeriodRemaining
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = getWMIObject -CimSession $CimSession -Query $query

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

function queryOfflineInstallationId
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT ID, OfflineInstallationId, PartialProductKey
    FROM SoftwareLicensingProduct
    WHERE (PartialProductKey <> null AND Name LIKE "Windows%")'

    $product = getWMIObject -CimSession $CimSession -Query $query

    $result = [PSCustomObject]@{
        'Offline Installation Id' = $product.OfflineInstallationId
    }
    return $result
}

#endregion Information functions

#region Utility functions

function getSession
{
    [CmdletBinding()]
    [OutputType([CimSession])]
    param (
        [string[]]
        $Computer,
        [Parameter(Mandatory = $false)]
        [PSCredential]
        $Credentials
    )

    Write-Verbose "Creating sessions for $($Computer.Count) hosts"

    if ($Computer.Count -eq 1 -and $Computer[0] -eq 'localhost' -or $Computer[0] -eq '.' -or $Computer[0] -eq '127.0.0.1' -or $null -eq $Computer[0])
    {
        Write-Verbose 'Using DCOM protocol for CIM session'
        if ($null -eq $Credentials)
        {
            $session = New-CimSession -Name 'SlmgrLocalSession'
        }
        else
        {
            $session = New-CimSession -Name 'SlmgrLocalSession' -Credential $Credentials
        }
    }
    else # if multiple hosts are given including localhost, then it will try to use WinRM, instead of DCOM.
    {
        Write-Verbose 'Using WinRM protocol for CIM session'
        $session = New-CimSession $PSBoundParameters -Name 'SlmgrRemoteSession'
    }
    return $session
}

# The WMI commands are not supported on PowerShell 6+ as they are deprecated -allegedly.
# They would work with PS5 though. To be safe, we used Get-CimInstance instead of 
# Get- WMIObject. Unfortunately, not all properties and methods are available on the CIM
# instances. Therefore, we convert the CIM instances to WMI objects to be able to access those methods.
# Reference: https://rohnspowershellblog.wordpress.com/2013/06/15/converting-a-ciminstance-to-a-managementobject-and-back/
function getWMIObject
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ClassName')]
        [string]$ClassName,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Query')]
        [string]$Query,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'InputObject')]
        [ValidateNotNull]
        [ciminstance]$InputObject
    )

    Process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Query')
        {
            $Instance = Get-CimInstance -CimSession $CimSession -Query $Query
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'ClassName')
        {
            $Instance = Get-CimInstance -CimSession $CimSession -ClassName $ClassName
        }
        else
        {
            $Instance = $InputObject
        }

        $Keys = $Instance.CimClass.CimClassProperties |
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
                    $Value = $Instance.$KeyName
                }

                'DateTime'
                {
                    # Conver to WMI datetime
                    $Value = '"{0}"' -f [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($Instance.$KeyName)
                }

                'Reference'
                {
                    throw "CimInstance contains a key with type 'Reference'. This isn't currenlty supported (but can be added later)"
                }

                default
                {
                    # Treat it like a string and cross your fingers:
                    $Value = '"{0}"' -f ($Instance.$KeyName -replace "`"", "\`"")
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

        return [wmi]('\\{0}\{1}:{2}{3}' -f $Instance.CimSystemProperties.ServerName,
                               ($Instance.CimSystemProperties.Namespace -replace '/', '\'),
            $Instance.CimSystemProperties.ClassName,
            $KeyValuePairsString)
    }
}
#endregion Utility functions

#endregion Private functions
