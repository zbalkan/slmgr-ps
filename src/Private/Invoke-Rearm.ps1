function Invoke-Rearm
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Service
    )

    $licenseInfo = Get-LicenseStatus -CimSession $CimSession
    $status = $licenseInfo.'License Status'
    if ($null -eq $status)
    {
        throw 'License status cannot be collected. It is suggested to restart computer.'
    }

    Write-Verbose "Current license status: $status"

    # Rearm is only meaningful for grace/non-genuine states, not Licensed or Notification
    $rearmableStatuses = @([LicenseStatusCode]::OOBGrace,
        [LicenseStatusCode]::OOTGrace,
        [LicenseStatusCode]::NonGenuineGrace,
        [LicenseStatusCode]::ExtendedGrace)
    $isRearmable = $status -in $rearmableStatuses
    Write-Verbose "Is rearmable: $isRearmable"

    if ($isRearmable -eq $false)
    {
        Write-Warning "Rearm is not applicable for the current license status: $status"
        return
    }

    try
    {
        if ($($Service | Invoke-CimMethod -MethodName ReArmWindows).ReturnValue -ne 0)
        {
            throw 'Failed to rearm Windows.'
        }
        $Service | Invoke-CimMethod -MethodName RefreshLicenseStatus | Out-Null
        Write-Verbose 'Command completed successfully.'
        Write-Verbose 'Please restart the system for the changes to take effect.'
    }
    catch
    {
        throw
    }
}
