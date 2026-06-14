function Get-WindowsLicensingProduct
{
    [OutputType([CimInstance])]
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    # ApplicationID '55c92734-d682-4d71-983e-d6ec3f16059f' is the Windows OS licensing application.
    # PartialProductKey IS NOT NULL ensures a product key is actually installed (excludes evaluation stubs).
    $query = "SELECT Name, Description, ID, ApplicationID, ProductKeyID, ProductKeyChannel,
    OfflineInstallationId, UseLicenseURL, ValidationURL, PartialProductKey,
    LicenseStatus, GracePeriodRemaining, RemainingAppReArmCount, RemainingSkuReArmCount, TrustedTime
    FROM SoftwareLicensingProduct
    WHERE ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'
    AND PartialProductKey IS NOT NULL"

    $candidates = @(Get-CimInstance -CimSession $CimSession -Query $query)

    if ($candidates.Count -eq 0)
    {
        throw 'No Windows licensing product with an installed product key was found. The system may be running an evaluation edition or have no key installed.'
    }

    if ($candidates.Count -eq 1)
    {
        return $candidates[0]
    }

    # Multiple products can appear after in-place upgrades. Prefer Licensed, then any active state.
    $licensed = @($candidates | Where-Object { $_.LicenseStatus -eq 1 })
    if ($licensed.Count -eq 1) { return $licensed[0] }

    $active = @($candidates | Where-Object { $_.LicenseStatus -ne 0 })
    if ($active.Count -eq 1) { return $active[0] }

    $summary = ($candidates | ForEach-Object { "'$($_.Name)' (status $($_.LicenseStatus))" }) -join ', '
    throw "Multiple Windows licensing products found and none can be selected unambiguously: $summary. Remove duplicate product registrations or contact your administrator."
}
