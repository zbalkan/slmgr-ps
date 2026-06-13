function Invoke-KMSActivation
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Service,
        [string]$KMSServerFQDN,
        [int]$KMSServerPort
    )

    # Check Windows Activation Status
    $licenseInfo = Get-LicenseStatus -CimSession $CimSession
    Write-Verbose "License Status: $($licenseInfo.'License Status')"
    if ($licenseInfo.Activated) { Write-Warning 'The product is already activated.'; return; }

    # Get product key
    $productKey = Get-KMSKey -CimSession $CimSession
    Write-Verbose "Product Key (for KMS): $productKey"

    if ($productKey -eq 'Unknown')
    {
        throw 'Unknown OS.'
    }
    else
    {
        # If provided, update values for Server FQDN and Port
        if ($PSBoundParameters.ContainsKey('KMSServerFQDN'))
        {
            $Service | Invoke-CimMethod -MethodName SetKeyManagementServiceMachine -Arguments @{ MachineName = $KMSServerFQDN } | Out-Null
        }
        if ($PSBoundParameters.ContainsKey('KMSServerPort'))
        {
            $Service | Invoke-CimMethod -MethodName SetKeyManagementServicePort -Arguments @{ PortNumber = $KMSServerPort } | Out-Null
        }

        $Service | Invoke-CimMethod -MethodName InstallProductKey -Arguments @{ ProductKey = $productKey } | Out-Null

        Start-Sleep -Seconds 10 # Installing product key takes time.
        $Service | Invoke-CimMethod -MethodName RefreshLicenseStatus | Out-Null
        Start-Sleep -Seconds 2

        # Trigger KMS network check-in via SoftwareLicensingProduct.Activate()
        $activationQuery = 'SELECT ID, LicenseStatus, Name
        FROM SoftwareLicensingProduct
        WHERE LicenseStatus <> 0 AND Name LIKE "Windows%"'
        $product = Get-CimInstance -CimSession $CimSession -Query $activationQuery | Select-Object -First 1
        $product | Invoke-CimMethod -MethodName Activate | Out-Null

        # Check Windows Activation Status
        $license = Get-LicenseStatus -CimSession $CimSession

        if ($license.Activated)
        {
            Write-Verbose "The computer activated successfully. Current status: $($license.'License Status')"
        }
        else
        {
            throw "Activation failed. Current status: $($license.'License Status')"
        }
    }
}
