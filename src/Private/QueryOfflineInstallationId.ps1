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
