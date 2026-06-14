function Invoke-OfflineActivation
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [string]$ConfirmationId,
        [CimInstance]$Service
    )

    $licenseInfo = Get-LicenseStatus -CimSession $CimSession
    Write-Verbose "License Status: $($licenseInfo.LicenseStatus)"
    if ($licenseInfo.Activated) { Write-Warning 'The product is already activated.'; return }

    $product = Get-WindowsLicensingProduct -CimSession $CimSession

    # Accept dashes, spaces, or plain digits; strip separators before submission
    $normalizedCid = $ConfirmationId -replace '[\s\-]', ''
    $installationId = (Get-OfflineInstallationId -CimSession $CimSession).OfflineInstallationId

    Write-Verbose 'Submitting activation and confirmation IDs...'
    Write-Debug "Offline Installation ID: $installationId"
    Write-Debug "Confirmation ID: $normalizedCid"

    $product | Invoke-SppCimMethod -MethodName DepositOfflineConfirmationId -Arguments @{
        InstallationId = $installationId
        ConfirmationId = $normalizedCid
    }

    Write-Verbose 'Updating the license status...'
    $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus
}
