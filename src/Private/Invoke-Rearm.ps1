function Invoke-Rearm
{
    [CmdletBinding()]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Service,
        [Guid]$ApplicationId,
        [Guid]$ActivationId
    )

    $hasApplicationId = $PSBoundParameters.ContainsKey('ApplicationId')
    $hasActivationId = $PSBoundParameters.ContainsKey('ActivationId')
    if ($hasApplicationId -and $hasActivationId)
    {
        throw 'ApplicationId and ActivationId cannot be used together for rearm.'
    }

    if ($hasApplicationId)
    {
        $Service | Invoke-SppCimMethod -MethodName ReArmApp `
            -Arguments @{ ApplicationId = $ApplicationId.ToString() }
        $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus
        Write-Verbose 'Application rearm completed. Restart the system for the change to take effect.'
        return [PSCustomObject]@{
            ActivationId      = $null
            ProductName       = $null
            VerificationState = 'ProviderAccepted'
            RestartRequired   = $true
        }
    }

    if ($hasActivationId)
    {
        $product = Get-WindowsLicensingProduct -CimSession $CimSession -ActivationId $ActivationId
        $product | Invoke-SppCimMethod -MethodName ReArmSku
        $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus
        Write-Verbose 'SKU rearm completed. Restart the system for the change to take effect.'
        return [PSCustomObject]@{
            ActivationId      = $ActivationId
            ProductName       = $product.Name
            VerificationState = 'ProviderAccepted'
            RestartRequired   = $true
        }
    }

    $licenseInfo = Get-LicenseStatus -CimSession $CimSession
    $status = $licenseInfo.LicenseStatus
    if ($null -eq $status)
    {
        throw 'License status cannot be collected. It is suggested to restart the computer.'
    }

    Write-Verbose "Current license status: $status"

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
        return [PSCustomObject]@{
            ActivationId      = $licenseInfo.ActivationId
            ProductName       = $licenseInfo.ProductName
            VerificationState = 'Verified'
            RestartRequired   = $false
        }
    }

    $Service | Invoke-SppCimMethod -MethodName ReArmWindows
    $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus
    Write-Verbose 'Rearm completed. Please restart the system for the changes to take effect.'
    return [PSCustomObject]@{
        ActivationId      = $licenseInfo.ActivationId
        ProductName       = $licenseInfo.ProductName
        VerificationState = 'ProviderAccepted'
        RestartRequired   = $true
    }
}
