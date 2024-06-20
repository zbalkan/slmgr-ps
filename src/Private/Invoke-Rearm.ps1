function Invoke-Rearm
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Service
    )

    $status = (Get-LicenseStatus -CimSession $CimSession).LicenseStatus
    if ($status -eq [LicenseStatusCode]::Unknown)
    {
        throw 'License status cannot be collected. It is suggested to restart computer.'
    }

    Write-Verbose "Current license status: $status"

    # Any status except Unknown, Licensed and Notification
    $rearmableStatuses = @([LicenseStatusCode]::Unlicensed,
        [LicenseStatusCode]::OOBGrace,
        [LicenseStatusCode]::OOTGrace,
        [LicenseStatusCode]::NonGenuineGrace,
        [LicenseStatusCode]::ExtendedGrace)
    $isRearmable = $status -in $rearmableStatuses
    Write-Verbose "Is rearmable: $isRearmable"

    if ($isRearmable -eq $false)
    {
        Write-Verbose 'No need to rearm.'
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
