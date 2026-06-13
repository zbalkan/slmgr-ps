function Get-ExpiryInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $product = Get-WindowsLicensingProduct -CimSession $CimSession
    $status = [LicenseStatusCode]($product.LicenseStatus)
    $graceRemaining = $product.GracePeriodRemaining

    $expirationInfo = switch ($product.LicenseStatus)
    {
        0 { [LicenseStatusCode]::Unlicensed.ToString() }
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
        2 { "Initial grace period ends $((Get-Date).AddMinutes($graceRemaining))" }
        3 { "Additional grace period ends $((Get-Date).AddMinutes($graceRemaining))" }
        4 { "Non-genuine grace period ends $((Get-Date).AddMinutes($graceRemaining))" }
        5 { 'Windows is in Notification mode' }
        6 { "Extended grace period ends $((Get-Date).AddMinutes($graceRemaining))" }
        Default { throw 'Unexpected license status' }
    }

    $result = [PSCustomObject]@{
        Name           = $product.Name
        LicenseStatus  = $status
        ExpirationInfo = $expirationInfo
    }
    return $result
}
