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
.INPUTS
string[]. You can pass the computer names
.OUTPUTS
None if successful. Error message if there is an error.
.EXAMPLE
Start-WindowsActivation -Verbose # Activates the local computer
.EXAMPLE
Start-WindowsActivation -Computer WS01 # Activates the computer named WS01
.EXAMPLE
Start-WindowsActivation -Computer WS01, WS02 -CacheEnabled $false # Disabled the KMS cache for the computers named WS01 and WS02. Cache is enabled by default.
.EXAMPLE
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500 # Activates the computer named WS01 against server.domain.net:2500
.EXAMPLE
Start-WindowsActivation -ReArm # ReArm the trial period. ReArming already licensed devices can break current license issues. Guard clauses wil protect 99% but cannot guarantee 100%.
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function global:Start-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High',
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
        $CacheEnabled
    )
    Begin
    {
    }
    Process
    {
        if ($pscmdlet.ShouldProcess($Computers -join ', ', 'Activate license via KMS'))
        {
            $ErrorActionPreference = 'Stop'
            Write-Verbose 'ErrorActionPreference: Stop'

            # Rearm can be run on trial versions only.
            # Try rearm and exit early.
            if ($PSCmdlet.ParameterSetName -eq 'Rearm')
            {
                try
                {
                    rearm -Computers $Computers
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
                    manageCache -Computer $Computer -Enabled $CacheEnabled
                    exit 0
                }
                catch
                {
                    exit 1
                }
            }

            # Activation
            activate -Computers $Computers -KMSServerFQDN $KMSServerFQDN -KMSServerPort $KMSServerPort
        }
    }
    End
    {
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
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function global:Get-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $true,
        ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [string[]]
        $Computers = @('localhost'),

        [Parameter(Mandatory = $false, ParameterSetName = 'Extended')]
        [switch]$Extended,

        [Parameter(Mandatory = $false, ParameterSetName = 'Expiry')]
        [switch]$Expiry

    )
    Begin
    {
    }
    Process
    {
        if ($pscmdlet.ShouldProcess('Computer', 'Collect license information'))
        {
            Write-Verbose "Enumerating computers: $($Computers.Count) computer(s)."
            foreach ($Computer in $Computers)
            {
                # Sanitize Computer name
                $Computer = sanitizeComputerName -Computer $Computer
                Write-Verbose "Computer name: $Computer"

                if ($Extended.IsPresent)
                {
                    return getExtendedLicenseInformation -Computer $Computer
                }
                elseif ($Expiry.IsPresent)
                {
                    return getExpiryInformation -Computer $Computer
                }
                else
                {
                    return getBasicLicenseInformation -Computer $Computer
                }
            }
        }
    }
    End
    {
    }
}



#region Private functions

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

    $query = 'SELECT LicenseStatus FROM SoftwareLicensingProduct
WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'
    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Query $query
    }
    else
    {
        $product = Get-CimInstance -Query $query -ComputerName $Computer
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


function activate
{
    param(
        [string[]]$Computers,
        [string]$KMSServerFQDN,
        [int]$KMSServerPort
    )

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
function getBasicLicenseInformation
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Computer
    )

    $basicQuery = 'SELECT Name,Description,PartialProductKey,LicenseStatus FROM SoftwareLicensingProduct
WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Query $basicQuery
    }
    else
    {
        $product = Get-CimInstance -Query $basicQuery -ComputerName $Computer
    }
    $name = $product.Name
    $desc = $product.Description
    $partial = $product.PartialProductKey
    $status = [LicenseStatusCode]( $product.LicenseStatus)

    $result = [PSCustomObject]@{
        Name              = $name
        Description       = $desc
        PartialProductKey = $partial
        LicenseStatus     = $status
    }
    return $result
}

function getExtendedLicenseInformation
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Computer
    )

    $extendedQuery = 'SELECT Name,Description,ID,ApplicationID,ProductKeyID,ProductKeyChannel,OfflineInstallationId,UseLicenseURL,ValidationURL,PartialProductKey,LicenseStatus,RemainingAppReArmCount,RemainingSkuReArmCount,TrustedTime FROM SoftwareLicensingProduct
WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Query $extendedQuery
    }
    else
    {
        $product = Get-CimInstance -Query $extendedQuery -ComputerName $Computer
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
    $trustedTime = [datetime]::Parse($product.Trustedtime)

    $result = [PSCustomObject]@{
        Name                       = $name
        Description                = $desc
        ActivationID               = $activationID
        ApplicationID              = $applicationID
        ProductKeyID               = $pkID
        ProductKeyChannel          = $pkChannel
        InstallationID             = $installationID
        UseLicenseURL              = $licenseUrl
        ValidationURL              = $validationUrl
        PartialProductKey          = $partial
        LicenseStatus              = $status
        RemainingWindowsRearmCount = $remainingAppRearm
        RemainingSkuRearmCount     = $remainingSkuRearm
        TrustedTime                = $trustedTime
    }
    return $result
}

function getExpiryInformation
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Computer
    )

    $expiryQuery = 'SELECT ID, ApplicationId, PartialProductKey, LicenseIsAddon, Description, Name, LicenseStatus, GracePeriodRemaining FROM SoftwareLicensingProduct
WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    if ($Computer -eq 'localhost')
    {
        $product = Get-CimInstance -Query $expiryQuery
    }
    else
    {
        $product = Get-CimInstance -Query $expiryQuery -ComputerName $Computer
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
            Write-Error -Message 'Unexpected license status'
        }
    }

    $result = [PSCustomObject]@{
        Name                  = $name
        LicenseStatus         = $status
        ExpirationInformation = $expirationInfo
    }
    return $result
}

# Reference: https://rohnspowershellblog.wordpress.com/2013/06/15/converting-a-ciminstance-to-a-managementobject-and-back/
function getCimPathFromInstance
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

        '\\{0}\{1}:{2}{3}' -f $InputObject.CimSystemProperties.ServerName,
                               ($InputObject.CimSystemProperties.Namespace -replace '/', '\'),
        $InputObject.CimSystemProperties.ClassName,
        $KeyValuePairsString
    }
}

function canRearm
{
    $status = (getLicenseStatus).LicenseStatus

    # Any status exvept Licensed and Notification
    $rearmableStatuses = @([LicenseStatusCode]::Unlicensed,
        [LicenseStatusCode]::OOBGrace,
        [LicenseStatusCode]::OOTGrace,
        [LicenseStatusCode]::NonGenuineGrace,
        [LicenseStatusCode]::ExtendedGrace)

    Write-Verbose "Current license status: $status"
    return ($status -in $rearmableStatuses)
}

function rearm
{
    param(
        [string[]]$Computers
    )

    Write-Verbose "Enumerating computers: $($Computers.Count) computer(s)."
    foreach ($Computer in $Computers)
    {
        # Sanitize Computer name
        $Computer = sanitizeComputerName -Computer $Computer
        Write-Verbose "Computer name: $Computer"
        if ($Computer -like 'localhost')
        {
            Write-Verbose 'Collecting data from local computer'
            $serviceInstance = [wmi] (Get-CimInstance -ClassName SoftwareLicensingService | getCimPathFromInstance)
        }
        else
        {
            Write-Verbose 'Collecting data from remote computer'
            $serviceInstance = [wmi] (Get-CimInstance -ClassName SoftwareLicensingService -ComputerName $Computer | getCimPathFromInstance)
        }

        $isRearmable = canRearm
        Write-Verbose "Is rearmable: $isRearmable"

        if ($isRearmable -eq $false)
        {
            Write-Verbose 'No need to rearm.'
            continue
        }

        if ($product.LicenseStatus -eq [LicenseStatusCode]::Unknown)
        {
            Write-Error 'License status cannot be collected. It is suggested to restart computer.'
            continue
        }

        try
        {
            [void]$serviceInstance.ReArmWindows()
            [void]$serviceInstance.RefreshLicenseStatus()
            Write-Verbose 'Command completed successfully.'
            Write-Verbose 'Please restart the system for the changes to take effect.'
        }
        catch [System.Management.Automation.MethodInvocationException]
        {
            Write-Error 'Rearm failed.'
        }
    }
}

function manageCache
{
    param(
        [string]$Computer,
        [bool]$Enabled
    )
    if ($Computer -eq 'localhost')
    {
        $service = Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingService'
    }
    else
    {
        $service = Get-CimInstance -Query 'SELECT * FROM SoftwareLicensingService' -ComputerName $Computer
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
#endregion
