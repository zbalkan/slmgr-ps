function Invoke-ProductKeyInstallation
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [CimInstance]$Service,

        [Parameter(Mandatory)]
        [string]$ProductKey
    )

    $Service | Invoke-SppCimMethod -MethodName InstallProductKey -Arguments @{
        ProductKey = $ProductKey
    }
    $Service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus
}
