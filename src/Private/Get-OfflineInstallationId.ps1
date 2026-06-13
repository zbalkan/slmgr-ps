function Get-OfflineInstallationId
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $product = Get-WindowsLicensingProduct -CimSession $CimSession

    $result = [PSCustomObject]@{
        OfflineInstallationId = $product.OfflineInstallationId
    }
    return $result
}
