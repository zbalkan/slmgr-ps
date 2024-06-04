function Get-BasicLicenseInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT ID,Name,Description,PartialProductKey,LicenseStatus
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = Get-CustomWMIObject -CimSession $CimSession -Query $query

    $name = $product.Name
    $desc = $product.Description
    $partial = $product.PartialProductKey
    $status = [LicenseStatusCode]($product.LicenseStatus)

    $result = [PSCustomObject]@{
        Name                  = $name
        Description           = $desc
        'Partial Product Key' = $partial
        'License Status'      = $status
    }
    return $result
}
