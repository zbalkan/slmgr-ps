function Get-OfflineInstallationId
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
        Name                  = $Product.Name
        ActivationId          = $Product.ID
        ApplicationId         = $Product.ApplicationID
        OfflineInstallationId = $Product.OfflineInstallationId
    }
    return $result
}
