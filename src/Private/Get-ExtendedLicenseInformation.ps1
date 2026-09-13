function Get-ExtendedLicenseInformation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [CimInstance]$Product,
        [CimInstance]$Service
    )

    if ($null -eq $Product)
    {
        $Product = Get-WindowsLicensingProduct -CimSession $CimSession
    }

    $trustedTime = [datetime]::MinValue
    if ($null -ne $Product.TrustedTime)
    {
        $trustedTime = $Product.TrustedTime
    }

    $configuredKmsPort = $Product.KeyManagementServicePort
    if ($configuredKmsPort -eq 0) { $configuredKmsPort = $null }
    $discoveredKmsPort = $Product.DiscoveredKeyManagementServiceMachinePort
    if ($discoveredKmsPort -eq 0) { $discoveredKmsPort = $null }
    $kmsHostCaching = $null
    if ($null -ne $Service -and
        $null -ne $Service.PSObject.Properties['KeyManagementServiceHostCaching'])
    {
        $kmsHostCaching = if ($Service.KeyManagementServiceHostCaching) { 'Enabled' } else { 'Disabled' }
    }

    $result = [PSCustomObject]@{
        Name                       = $Product.Name
        Description                = $Product.Description
        ActivationId               = $Product.ID
        ApplicationId              = $Product.ApplicationID
        ExtendedPid                = $Product.ProductKeyID
        ProductKeyChannel          = $Product.ProductKeyChannel
        InstallationId             = $Product.OfflineInstallationId
        UseLicenseUrl              = $Product.UseLicenseURL
        ValidationUrl              = $Product.ValidationURL
        PartialProductKey          = $Product.PartialProductKey
        LicenseStatus              = [LicenseStatusCode]($Product.LicenseStatus)
        RemainingWindowsRearmCount = $Product.RemainingAppReArmCount
        RemainingSkuRearmCount     = $Product.RemainingSkuReArmCount
        TrustedTime                = $trustedTime
        ConfiguredKmsHost          = $Product.KeyManagementServiceMachine
        ConfiguredKmsPort          = $configuredKmsPort
        DiscoveredKmsHost          = $Product.DiscoveredKeyManagementServiceMachineName
        DiscoveredKmsPort          = $discoveredKmsPort
        KmsLookupDomain            = $Product.KeyManagementServiceLookupDomain
        KmsHostCaching             = $kmsHostCaching
    }
    return $result
}
