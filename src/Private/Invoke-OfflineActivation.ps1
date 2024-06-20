function Invoke-OfflineActivation
{
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [string]$ConfirmationId,
        [CimInstance]$Service
    )

    # Check Windows Activation Status
    $status = (Get-LicenseStatus -CimSession $CimSession).LicenseStatus
    Write-Verbose "License Status: $($status)"
    if ($status.Activated) { Write-Warning 'The product is already activated.'; return; }

    $query = 'SELECT ID, Name, PartialProductKey
    FROM SoftwareLicensingProduct
    WHERE (PartialProductKey <> null AND Name LIKE "Windows%")'

    Write-Verbose 'Connecting to computer...'
    $product = Get-CimInstance -CimSession $CimSession -Query $query

    $InstallationId = (Get-OfflineInstallationId -CimSession $CimSession).'Offline Installation Id'
    Write-Verbose 'Submitting activation and confirmation IDs...'
    Write-Debug 'Offline Installation ID: $InstallationId'
    Write-Debug 'Confirmation ID: $ConfirmationId'

    $arguments = @{
        InstallationId = $InstallationId
        ConfirmationId = $ConfirmationId
    }

    try
    {
        if ($(($product | Invoke-CimMethod -MethodName DepositOfflineConfirmationId -Arguments $arguments)).ReturnValue -ne 0)
        { throw 'Failed to activate with offline activation. Check the Confirmation ID.' }
    }
    catch { throw }

    Write-Verbose 'Updating the license status...'
    $Service | Invoke-CimMethod -MethodName RefreshLicenseStatus
}
