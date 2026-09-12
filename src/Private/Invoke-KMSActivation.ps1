function Invoke-KMSActivation
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Service,
        [string]$KMSServerFQDN,
        [int]$KMSServerPort,
        [switch]$InstallKmsClientKey,
        [string]$ProductKey,
        [Guid]$ActivationId
    )

    if ($InstallKmsClientKey.IsPresent -and $PSBoundParameters.ContainsKey('ProductKey'))
    {
        throw 'InstallKmsClientKey and ProductKey cannot be used together.'
    }

    $installRequested = $InstallKmsClientKey.IsPresent -or $PSBoundParameters.ContainsKey('ProductKey')
    if ($installRequested -and $PSBoundParameters.ContainsKey('ActivationId'))
    {
        throw 'ActivationId cannot be combined with product-key installation because InstallProductKey is service-scoped.'
    }
    $kmsSettingsRequested = $PSBoundParameters.ContainsKey('KMSServerFQDN')
    if ($PSBoundParameters.ContainsKey('KMSServerPort')) { $kmsSettingsRequested = $true }
    $statusParams = @{ CimSession = $CimSession }
    if ($PSBoundParameters.ContainsKey('ActivationId')) { $statusParams['ActivationId'] = $ActivationId }
    $product = $null
    if ($PSBoundParameters.ContainsKey('ActivationId'))
    {
        $product = Get-WindowsLicensingProduct -CimSession $CimSession -ActivationId $ActivationId
    }
    if (-not $installRequested)
    {
        $licenseInfo = Get-LicenseStatus @statusParams
        Write-Verbose "License Status: $($licenseInfo.LicenseStatus)"
        if ($licenseInfo.Activated -and -not $kmsSettingsRequested)
        {
            Write-Warning 'The product is already activated.'
            return
        }
    }

    if ($PSBoundParameters.ContainsKey('KMSServerFQDN'))
    {
        $kmsTarget = if ($null -ne $product) { $product } else { $Service }
        $kmsTarget | Invoke-SppCimMethod -MethodName SetKeyManagementServiceMachine -Arguments @{ MachineName = $KMSServerFQDN }
        # Always set the port when changing the FQDN: without this, a stale non-default port
        # from a previous call would be reused, silently targeting the wrong endpoint.
        $effectivePort = if ($PSBoundParameters.ContainsKey('KMSServerPort')) { $KMSServerPort } else { 1688 }
        $kmsTarget | Invoke-SppCimMethod -MethodName SetKeyManagementServicePort -Arguments @{ PortNumber = $effectivePort }
    }
    elseif ($PSBoundParameters.ContainsKey('KMSServerPort'))
    {
        $kmsTarget = if ($null -ne $product) { $product } else { $Service }
        $kmsTarget | Invoke-SppCimMethod -MethodName SetKeyManagementServicePort -Arguments @{ PortNumber = $KMSServerPort }
    }

    if ($installRequested)
    {
        $keyToInstall = $ProductKey
        if ($InstallKmsClientKey.IsPresent)
        {
            $keyToInstall = Get-KMSKey -CimSession $CimSession
            if ($keyToInstall -eq 'Unknown')
            {
                throw 'No KMS client setup key is available for this OS edition. Provide a product key manually or use a recognised edition.'
            }
        }

        Write-Verbose 'Installing product key'
        $Service | Invoke-SppCimMethod -MethodName InstallProductKey -Arguments @{ ProductKey = $keyToInstall }
        Start-Sleep -Seconds 10 # Installing product key takes time.
        $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus
        Start-Sleep -Seconds 2
    }

    # Activate the product selected after any requested key installation.
    if ($null -eq $product) { $product = Get-WindowsLicensingProduct -CimSession $CimSession }
    $product | Invoke-SppCimMethod -MethodName Activate
    $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus

    $license = Get-LicenseStatus @statusParams
    if ($license.Activated)
    {
        Write-Verbose "The computer activated successfully. Current status: $($license.LicenseStatus)"
    }
    else
    {
        throw "Activation failed. Current status: $($license.LicenseStatus)"
    }
}
