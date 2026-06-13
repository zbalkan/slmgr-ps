function Get-LicenseStatus
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $product = Get-WindowsLicensingProduct -CimSession $CimSession
    $status = [LicenseStatusCode]($product.LicenseStatus)
    $activated = $status -eq [LicenseStatusCode]::Licensed
    $result = [PSCustomObject]@{
        LicenseStatus = $status
        Activated     = $activated
    }
    return $result
}
