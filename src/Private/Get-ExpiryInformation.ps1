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

    $product = Get-CimInstance -CimSession $CimSession -Query $query | Select-Object -First 1

    $name = $product.Name
    $status = [LicenseStatusCode]($product.LicenseStatus)
    $graceRemaining = $product.GracePeriodRemaining

    $expirationInfo = switch ($product.LicenseStatus)
    {
        1
        {
            if ($null -eq $graceRemaining -or $graceRemaining -eq 0)
            {
                'The machine is permanently activated.'
            }
            else
            {
                $endDate = (Get-Date).AddMinutes($graceRemaining)
                if ($product.Description -imatch 'TIMEBASED_')
                {
                    "Timebased activation will expire $endDate"
                }
                elseif ($product.Description -imatch 'VIRTUAL_MACHINE_ACTIVATION')
                {
                    "Automatic VM activation will expire $endDate"
                }
                else
                {
                    "Volume activation will expire $endDate"
                }
            }
        }
        2 { $endDate = (Get-Date).AddMinutes($graceRemaining); "Initial grace period ends $endDate" }
        3 { $endDate = (Get-Date).AddMinutes($graceRemaining); "Additional grace period ends $endDate" }
        4 { $endDate = (Get-Date).AddMinutes($graceRemaining); "Non-genuine grace period ends $endDate" }
        5 { 'Windows is in Notification mode' }
        6 { $endDate = (Get-Date).AddMinutes($graceRemaining); "Extended grace period ends $endDate" }
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
