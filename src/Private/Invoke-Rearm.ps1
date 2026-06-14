function Invoke-Rearm
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Service
    )

    $licenseInfo = Get-LicenseStatus -CimSession $CimSession
    $status = $licenseInfo.LicenseStatus
    if ($null -eq $status)
    {
        throw 'License status cannot be collected. It is suggested to restart the computer.'
    }

    Write-Verbose "Current license status: $status"

    # Rearm is only meaningful for grace and non-genuine states
    $rearmableStatuses = @(
        [LicenseStatusCode]::OOBGrace,
        [LicenseStatusCode]::OOTGrace,
        [LicenseStatusCode]::NonGenuineGrace,
        [LicenseStatusCode]::ExtendedGrace
    )
    $isRearmable = $status -in $rearmableStatuses
    Write-Verbose "Is rearmable: $isRearmable"

    if (-not $isRearmable)
    {
        Write-Warning "Rearm is not applicable for the current license status: $status"
        return
    }

    $Service | Invoke-SppCimMethod -MethodName ReArmWindows
    $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus
    Write-Verbose 'Rearm completed. Please restart the system for the changes to take effect.'
}
