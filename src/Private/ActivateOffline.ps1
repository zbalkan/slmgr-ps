function activateOffline
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [string]$ConfirmationId,
        [wmi]$Service
    )

    # Check Windows Activation Status
    $status = (queryLicenseStatus -CimSession $CimSession).LicenseStatus
    Write-Verbose "License Status: $($status)"
    if ($status.Activated) { Write-Warning 'The product is already activated.'; return; }

    $query = "SELECT Version
    FROM SoftwareLicensingProduct
    WHERE PartialProductKey <> null AND Name LIKE 'Win%'"

    Write-Verbose 'Connecting to computer...'
    $product = getWMIObject -CimSession $CimSession -Query $query

    $InstallationId = (queryOfflineInstallationId -CimSession $CimSession).'Offline Installation Id'
    Write-Verbose 'Submitting activation and confirmation IDs...'
    Write-Debug 'Offline Installation ID: $InstallationId'
    Write-Debug 'Confirmation ID: $ConfirmationId'

    if ([int]$product.DepositOfflineConfirmationId($InstallationId, $ConfirmationId) -ne 0)
    {
        throw 'Failed to activate with offline activation. Check the Confirmation ID.'
    }
    Write-Verbose 'Updating the license status...'
    [void]$Service.RefreshLicenseStatus()
    [void]$product.refresh_ # Not sure if it is an undocumented internal command. I have found this gem in slmgr.vbs
}
