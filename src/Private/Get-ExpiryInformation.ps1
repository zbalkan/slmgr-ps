function Get-ExpiryInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $query = 'SELECT ID, Description, Name, LicenseStatus, GracePeriodRemaining
    FROM SoftwareLicensingProduct
    WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'

    $product = Get-CustomWMIObject -CimSession $CimSession -Query $query

    $name = $product.Name
    $status = [LicenseStatusCode]($product.LicenseStatus)
    $graceRemaining = $product.GracePeriodRemaining
    $endDate = (Get-Date).AddMinutes($graceRemaining)

    $expirationInfo = switch ($product.LicenseStatus)
    {
        0 { [LicenseStatusCode]::Unlicensed.ToString() }
        1
        {
            if ($graceRemaining -eq 0)
            {
                'The machine is permanently activated.'
            }
            else
            {
                if ($product.Description -icontains 'TIMEBASED_')
                {
                    "Timebased activation will expire $endDate"
                }
                elif($product.Description -icontains 'VIRTUAL_MACHINE_ACTIVATION') {
                    "Automatic VM activation will expire $endDate"
                }
                else {
                    "Volume activation will expire $endDate"
                }
            }
        }
        2 { "Initial grace period ends $endDate" }
        3 { "Additional grace period ends $endDate" }
        4 { "Non-genuine grace period ends $endDate" }
        5 { 'Windows is in Notification mode' }
        6 { "Extended grace period ends $endDate" }
        Default
        {
            throw 'Unexpected license status'
        }
    }

    $result = [PSCustomObject]@{
        Name                     = $name
        'License Status'         = $status
        'Expiration Information' = $expirationInfo
    }
    return $result
}
