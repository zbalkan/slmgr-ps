function Get-LicenseStatus
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [Guid]$ActivationId
    )

    $productParams = @{ CimSession = $CimSession }
    if ($PSBoundParameters.ContainsKey('ActivationId')) { $productParams['ActivationId'] = $ActivationId }
    $product = Get-WindowsLicensingProduct @productParams
    $status = [LicenseStatusCode]($product.LicenseStatus)
    $activated = $status -eq [LicenseStatusCode]::Licensed
    $result = [PSCustomObject]@{
        ActivationId  = $product.ID
        ProductName   = $product.Name
        LicenseStatus = $status
        Activated     = $activated
    }
    return $result
}
