function Invoke-OfflineActivation
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [string]$ConfirmationId,
        [CimInstance]$Service
    )

    # Check Windows Activation Status
    $licenseInfo = Get-LicenseStatus -CimSession $CimSession
    Write-Verbose "License Status: $($licenseInfo.'License Status')"
    if ($licenseInfo.Activated) { Write-Warning 'The product is already activated.'; return; }

    $query = 'SELECT ID, Name, PartialProductKey
    FROM SoftwareLicensingProduct
    WHERE (PartialProductKey IS NOT NULL AND Name LIKE "Windows%")'

    Write-Verbose 'Connecting to computer...'
    $product = Get-CimInstance -CimSession $CimSession -Query $query | Select-Object -First 1

    $InstallationId = (Get-OfflineInstallationId -CimSession $CimSession).'Offline Installation Id'
    Write-Verbose 'Submitting activation and confirmation IDs...'
    Write-Debug "Offline Installation ID: $InstallationId"
    Write-Debug "Confirmation ID: $ConfirmationId"

    $arguments = @{
        InstallationId = $InstallationId
        ConfirmationId = $ConfirmationId
    }

    if (($product | Invoke-CimMethod -MethodName DepositOfflineConfirmationId -Arguments $arguments).ReturnValue -ne 0)
    {
        throw 'Failed to activate with offline activation. Check the Confirmation ID.'
    }

    Write-Verbose 'Updating the license status...'
    $Service | Invoke-CimMethod -MethodName RefreshLicenseStatus | Out-Null
}
