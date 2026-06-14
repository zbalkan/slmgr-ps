function Get-BasicLicenseInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $product = Get-WindowsLicensingProduct -CimSession $CimSession

    $result = [PSCustomObject]@{
        Name              = $product.Name
        Description       = $product.Description
        PartialProductKey = $product.PartialProductKey
        LicenseStatus     = [LicenseStatusCode]($product.LicenseStatus)
    }
    return $result
}
