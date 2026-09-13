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

    $trustedTime = $Product.TrustedTime
    if ($null -eq $trustedTime -or $trustedTime -eq [datetime]::MinValue) { $trustedTime = $null }

    $evaluationEndDate = $Product.EvaluationEndDate
    if ($null -eq $evaluationEndDate -or $evaluationEndDate -eq [datetime]::MinValue)
    {
        $evaluationEndDate = $null
    }

    $configuredKmsPort = $Product.KeyManagementServicePort
    if ($configuredKmsPort -eq 0) { $configuredKmsPort = $null }
    $discoveredKmsPort = $Product.DiscoveredKeyManagementServiceMachinePort
    if ($discoveredKmsPort -eq 0) { $discoveredKmsPort = $null }

    $configuredActivationTypeCode = $Product.VLActivationTypeEnabled
    $configuredActivationType = switch ($configuredActivationTypeCode)
    {
        0 { 'Any' }
        1 { 'ActiveDirectory' }
        2 { 'Kms' }
        3 { 'Token' }
        default { $null }
    }

    $kmsHostCaching = $null
    $serviceVersion = $null
    $clientMachineId = $null
    $remainingWindowsRearmCount = $null
    $isKmsHost = $null
    if ($null -ne $Service)
    {
        if ($null -ne $Service.PSObject.Properties['KeyManagementServiceHostCaching'])
        {
            $kmsHostCaching = if ($Service.KeyManagementServiceHostCaching) { 'Enabled' } else { 'Disabled' }
        }
        if ($null -ne $Service.PSObject.Properties['Version'])
        {
            $serviceVersion = $Service.Version
        }
        if ($null -ne $Service.PSObject.Properties['ClientMachineID'])
        {
            $clientMachineId = $Service.ClientMachineID
        }
        if ($null -ne $Service.PSObject.Properties['RemainingWindowsReArmCount'])
        {
            $remainingWindowsRearmCount = $Service.RemainingWindowsReArmCount
        }
        if ($null -ne $Service.PSObject.Properties['IsKeyManagementServiceMachine'])
        {
            $isKmsHost = [bool]$Service.IsKeyManagementServiceMachine
        }
    }

    $result = [PSCustomObject]@{
        Name                         = $Product.Name
        Description                  = $Product.Description
        ActivationId                 = $Product.ID
        ApplicationId                = $Product.ApplicationID
        ExtendedPid                  = $Product.ProductKeyID
        ProductKeyChannel            = $Product.ProductKeyChannel
        InstallationId               = $Product.OfflineInstallationId
        UseLicenseUrl                = $Product.UseLicenseURL
        ValidationUrl                = $Product.ValidationURL
        PartialProductKey            = $Product.PartialProductKey
        LicenseStatusCode            = [uint32]$Product.LicenseStatus
        LicenseStatus                = [LicenseStatusCode]($Product.LicenseStatus)
        LicenseStatusReason          = $Product.LicenseStatusReason
        GracePeriodRemaining         = $Product.GracePeriodRemaining
        EvaluationEndDate            = $evaluationEndDate
        RemainingWindowsRearmCount   = $remainingWindowsRearmCount
        RemainingAppRearmCount       = $Product.RemainingAppReArmCount
        RemainingSkuRearmCount       = $Product.RemainingSkuReArmCount
        TrustedTime                  = $trustedTime
        ServiceVersion               = $serviceVersion
        ClientMachineId              = $clientMachineId
        IsKmsHost                    = $isKmsHost
        VlActivationInterval         = $Product.VLActivationInterval
        VlRenewalInterval            = $Product.VLRenewalInterval
        LastVolumeActivationTypeCode = $Product.VLActivationType
        ActivationTypePolicyCode     = $configuredActivationTypeCode
        ActivationTypePolicy         = $configuredActivationType
        ConfiguredKmsHost            = $Product.KeyManagementServiceMachine
        ConfiguredKmsPort            = $configuredKmsPort
        DiscoveredKmsHost            = $Product.DiscoveredKeyManagementServiceMachineName
        DiscoveredKmsPort            = $discoveredKmsPort
        KmsLookupDomain              = $Product.KeyManagementServiceLookupDomain
        KmsHostCaching               = $kmsHostCaching
    }
    return $result
}
