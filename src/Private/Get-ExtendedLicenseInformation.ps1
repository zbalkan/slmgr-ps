function Get-ExtendedLicenseInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $product = Get-WindowsLicensingProduct -CimSession $CimSession

    $trustedTime = [datetime]::MinValue
    if ($null -ne $product.TrustedTime)
    {
        $trustedTime = $product.TrustedTime
    }

    $result = [PSCustomObject]@{
        Name                       = $product.Name
        Description                = $product.Description
        ActivationId               = $product.ID
        ApplicationId              = $product.ApplicationID
        ExtendedPid                = $product.ProductKeyID
        ProductKeyChannel          = $product.ProductKeyChannel
        InstallationId             = $product.OfflineInstallationId
        UseLicenseUrl              = $product.UseLicenseURL
        ValidationUrl              = $product.ValidationURL
        PartialProductKey          = $product.PartialProductKey
        LicenseStatus              = [LicenseStatusCode]($product.LicenseStatus)
        RemainingWindowsRearmCount = $product.RemainingAppReArmCount
        RemainingSkuRearmCount     = $product.RemainingSkuReArmCount
        TrustedTime                = $trustedTime
    }
    return $result
}
