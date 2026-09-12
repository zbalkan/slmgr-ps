function Get-BasicLicenseInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Product
    )

    if ($null -eq $Product)
    {
        $Product = Get-WindowsLicensingProduct -CimSession $CimSession
    }

    $result = [PSCustomObject]@{
        Name              = $Product.Name
        Description       = $Product.Description
        ActivationId      = $Product.ID
        ApplicationId     = $Product.ApplicationID
        PartialProductKey = $Product.PartialProductKey
        LicenseStatus     = [LicenseStatusCode]($Product.LicenseStatus)
    }
    return $result
}
