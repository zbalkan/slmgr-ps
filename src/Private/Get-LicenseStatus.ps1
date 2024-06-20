function Get-LicenseStatus
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT ID, LicenseStatus, Name
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = Get-CimInstance -CimSession $CimSession -Query $query

    $status = [LicenseStatusCode]($product.LicenseStatus).LicenseStatus
    $activated = $status -eq [LicenseStatusCode]::Licensed
    $result = [PSCustomObject]@{
        'License Status' = $status
        Activated        = $activated
    }
    return $result
}
