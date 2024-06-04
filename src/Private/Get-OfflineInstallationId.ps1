function Get-OfflineInstallationId
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT ID, Name, OfflineInstallationId, PartialProductKey
    FROM SoftwareLicensingProduct
    WHERE (PartialProductKey <> null AND Name LIKE "Windows%")'

    $product = Get-CustomWMIObject -CimSession $CimSession -Query $query

    $result = [PSCustomObject]@{
        'Offline Installation Id' = $product.OfflineInstallationId
    }
    return $result
}
