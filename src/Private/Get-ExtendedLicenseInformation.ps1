function Get-ExtendedLicenseInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT Name,Description,ID,ApplicationID,ProductKeyID,ProductKeyChannel,OfflineInstallationId,UseLicenseURL,ValidationURL,PartialProductKey,LicenseStatus,RemainingAppReArmCount,RemainingSkuReArmCount,TrustedTime
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = Get-CustomWMIObject -CimSession $CimSession -Query $query

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
    $trustedTime = [datetime]::MinValue
    if ([string]::IsNullOrEmpty($product.TrustedTime) -eq $false)
    {
        $trustedTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($product.Trustedtime)
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
