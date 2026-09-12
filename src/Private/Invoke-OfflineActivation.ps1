function Invoke-OfflineActivation
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [string]$ConfirmationId,
        [CimInstance]$Service,
        [Guid]$ActivationId
    )

    $targetParams = @{ CimSession = $CimSession }
    if ($PSBoundParameters.ContainsKey('ActivationId')) { $targetParams['ActivationId'] = $ActivationId }

    $licenseInfo = Get-LicenseStatus @targetParams
    Write-Verbose "License Status: $($licenseInfo.LicenseStatus)"
    if ($licenseInfo.Activated) { Write-Warning 'The product is already activated.'; return }

    $product = Get-WindowsLicensingProduct @targetParams

    # Accept dashes, spaces, or plain digits; strip separators before submission
    $normalizedCid = $ConfirmationId -replace '[\s\-]', ''
    $installationId = (Get-OfflineInstallationId -CimSession $CimSession -Product $product).OfflineInstallationId

    Write-Verbose 'Submitting activation and confirmation IDs...'
    Write-Debug "Offline Installation ID: $installationId"

    $product | Invoke-SppCimMethod -MethodName DepositOfflineConfirmationId -Arguments @{
        InstallationId = $installationId
        ConfirmationId = $normalizedCid
    }

    Write-Verbose 'Updating the license status...'
    $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus

    $finalLicenseInfo = Get-LicenseStatus @targetParams
    if ($finalLicenseInfo.LicenseStatus -eq [LicenseStatusCode]::Licensed)
    {
        Write-Verbose 'Offline activation completed successfully.'
    }
    elseif ($finalLicenseInfo.LicenseStatus -eq [LicenseStatusCode]::ExtendedGrace)
    {
        Write-Warning 'Offline activation completed, but Windows remains in extended grace.'
    }
    else
    {
        throw "Offline activation failed. Current status: $($finalLicenseInfo.LicenseStatus)"
    }
}
