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
    $status = (Get-LicenseStatus -CimSession $CimSession).LicenseStatus
    Write-Verbose "License Status: $($status)"
    if ($status.Activated) { Write-Warning 'The product is already activated.'; return; }

    # Get product key
    $productKey = Get-KMSKey -CimSession $CimSession
    Write-Verbose "Product Key (for KMS): $productKey"

    # Activate Windows
    if ($productKey -eq 'Unknown')
    {
        throw 'Unknown OS.'
    }
    else
    {
        # If provided, u[date values for Server FQDN and Port
        if ($PSBoundParameters.ContainsKey('KMSServerFQDN'))
        {
            $service | Invoke-CimMethod -MethodName SetKeyManagementServiceMachine -Arguments @{ MachineName = $KeyServerPort }
        }
        if ($PSBoundParameters.ContainsKey('KeyServerPort'))
        {
            $service | Invoke-CimMethod -MethodName SetKeyManagementServicePort -Arguments @{ PortNumber = $KeyServerPort }
        }

        $service | Invoke-CimMethod -MethodName InstallProductKey -Arguments @{ $ProductKey = $ProductKey } | Out-Null

        Start-Sleep -Seconds 10 # Installing product key takes time.
        $service | Invoke-CimMethod -MethodName RefreshLicenseStatus | Out-Null
        Start-Sleep -Seconds 2 # It also takes time.


        # Check Windows Activation Status
        $license = Get-LicenseStatus -CimSession $CimSession

        if ($license.Activated)
        {
            Write-Verbose "The computer activated succesfully. Current status: $($license.LicenseStatus)"
        }
        else
        {
            throw "Activation failed. Current status: $($license.LicenseStatus)"
        }
    }
}
