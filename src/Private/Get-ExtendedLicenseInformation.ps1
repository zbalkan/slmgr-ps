function Get-ExtendedLicenseInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Product
    )

    if ($null -eq $Product)
    {
        $Product = Get-WindowsLicensingProduct -CimSession $CimSession
    }

    $trustedTime = [datetime]::MinValue
    if ($null -ne $Product.TrustedTime)
    {
        $trustedTime = $Product.TrustedTime
    }

    $result = [PSCustomObject]@{
        Name                       = $Product.Name
        Description                = $Product.Description
        ActivationId               = $Product.ID
        ApplicationId              = $Product.ApplicationID
        ExtendedPid                = $Product.ProductKeyID
        ProductKeyChannel          = $Product.ProductKeyChannel
        InstallationId             = $Product.OfflineInstallationId
        UseLicenseUrl              = $Product.UseLicenseURL
        ValidationUrl              = $Product.ValidationURL
        PartialProductKey          = $Product.PartialProductKey
        LicenseStatus              = [LicenseStatusCode]($Product.LicenseStatus)
        RemainingWindowsRearmCount = $Product.RemainingAppReArmCount
        RemainingSkuRearmCount     = $Product.RemainingSkuReArmCount
        TrustedTime                = $trustedTime
    }
    return $result
}
