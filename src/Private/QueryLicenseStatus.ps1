function queryLicenseStatus
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT LicenseStatus
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = getWMIObject -CimSession $CimSession -Query $query

    $status = [LicenseStatusCode]($product | Select-Object LicenseStatus).LicenseStatus
    $activated = $status -eq [LicenseStatusCode]::Licensed
    $result = [PSCustomObject]@{
        'License Status' = $status
        Activated        = $activated
    }
    return $result
}