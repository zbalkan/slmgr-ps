function Get-OfflineInstallationId
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT ID, Name, OfflineInstallationId, PartialProductKey
    FROM SoftwareLicensingProduct
    WHERE (PartialProductKey IS NOT NULL AND Name LIKE "Windows%")'

    $product = Get-CimInstance -CimSession $CimSession -Query $query | Select-Object -First 1

    $result = [PSCustomObject]@{
        'Offline Installation Id' = $product.OfflineInstallationId
    }
    return $result
}
