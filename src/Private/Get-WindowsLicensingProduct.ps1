function Get-WindowsLicensingProduct
{
    [OutputType([CimInstance])]
    [CmdletBinding(DefaultParameterSetName = 'DefaultMutation')]
    param(
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,

        [Parameter(Mandatory, ParameterSetName = 'DefaultRead')]
        [switch]$ForRead,

        [Parameter(Mandatory, ParameterSetName = 'ByActivationId')]
        [Guid]$ActivationId,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All,

        [Parameter(Mandatory, ParameterSetName = 'ByPartialProductKey')]
        [ValidatePattern('^[A-Za-z0-9]{5}$')]
        [string]$PartialProductKey,

        [Parameter(ParameterSetName = 'ByActivationId')]
        [switch]$RequireProductKey
    )

    $properties = @(
        'Name', 'Description', 'ID', 'ApplicationID', 'LicenseIsAddon',
        'ProductKeyID', 'ProductKeyChannel', 'OfflineInstallationId',
        'UseLicenseURL', 'ValidationURL', 'PartialProductKey', 'LicenseStatus',
        'LicenseStatusReason', 'GracePeriodRemaining', 'EvaluationEndDate',
        'RemainingAppReArmCount', 'RemainingSkuReArmCount', 'TrustedTime',
        'VLActivationInterval', 'VLRenewalInterval',
        'VLActivationType', 'VLActivationTypeEnabled',
        'TokenActivationILID', 'TokenActivationILVID',
        'TokenActivationGrantNumber', 'TokenActivationCertificateThumbprint',
        'TokenActivationAdditionalInfo',
        'ADActivationObjectName', 'ADActivationObjectDN',
        'ADActivationCsvlkPid', 'ADActivationCsvlkSkuId',
        'KeyManagementServiceMachine', 'KeyManagementServicePort',
        'DiscoveredKeyManagementServiceMachineName',
        'DiscoveredKeyManagementServiceMachinePort',
        'KeyManagementServiceLookupDomain'
    )
    $query = "SELECT $($properties -join ', ') FROM SoftwareLicensingProduct"

    $windowsApplicationId = '55c92734-d682-4d71-983e-d6ec3f16059f'
    $whereClauses = switch ($PSCmdlet.ParameterSetName)
    {
        'ByActivationId'
        {
            $clauses = @("ID = '$($ActivationId.ToString())'")
            if ($RequireProductKey.IsPresent) { $clauses += 'PartialProductKey IS NOT NULL' }
            $clauses
        }
        'All' { @() }
        'ByPartialProductKey'
        {
            @(
                "ApplicationID = '$windowsApplicationId'"
                "PartialProductKey = '$($PartialProductKey.ToUpperInvariant())'"
                'LicenseIsAddon = FALSE'
            )
        }
        'DefaultRead'
        {
            @(
                "ApplicationID = '$windowsApplicationId'"
                'PartialProductKey IS NOT NULL'
            )
        }
        default
        {
            @(
                "ApplicationID = '$windowsApplicationId'"
                'PartialProductKey IS NOT NULL'
                'LicenseIsAddon = FALSE'
            )
        }
    }

    if ($whereClauses.Count -gt 0)
    {
        $query += " WHERE $($whereClauses -join ' AND ')"
    }

    $candidates = @(Get-CimInstance -CimSession $CimSession -Query $query -ErrorAction Stop)

    if ($PSCmdlet.ParameterSetName -eq 'All')
    {
        return $candidates | Sort-Object ApplicationID, Name, ID
    }

    if ($PSCmdlet.ParameterSetName -eq 'ByActivationId')
    {
        if ($candidates.Count -eq 0)
        {
            throw "Licensing product with activation ID $ActivationId was not found."
        }
        if ($candidates.Count -ne 1)
        {
            throw "Multiple licensing products returned for activation ID $ActivationId."
        }
        return $candidates[0]
    }

    if ($PSCmdlet.ParameterSetName -eq 'ByPartialProductKey')
    {
        if ($candidates.Count -eq 0)
        {
            throw "Windows licensing product with partial product key $PartialProductKey was not found after installation."
        }
        if ($candidates.Count -ne 1)
        {
            throw "Multiple Windows licensing products have partial product key $PartialProductKey; activation cannot continue safely."
        }
        return $candidates[0]
    }

    $baseCandidates = @($candidates | Where-Object { $_.LicenseIsAddon -ne $true })
    if ($baseCandidates.Count -eq 0)
    {
        throw 'No Windows licensing product with an installed product key was found. The system may be running an evaluation edition or have no key installed.'
    }

    if ($baseCandidates.Count -eq 1)
    {
        $selectedProduct = $baseCandidates[0]
    }
    else
    {
        $licensed = @($baseCandidates | Where-Object { $_.LicenseStatus -eq 1 })
        if ($licensed.Count -eq 1)
        {
            $selectedProduct = $licensed[0]
        }
        else
        {
            $active = @($baseCandidates | Where-Object { $_.LicenseStatus -ne 0 })
            if ($active.Count -eq 1) { $selectedProduct = $active[0] }
        }
    }

    if ($null -eq $selectedProduct)
    {
        $summary = ($baseCandidates | ForEach-Object {
                $id = if ($null -eq $_.ID) { '<unknown>' } else { $_.ID }
                "'$($_.Name)' ($id, status $($_.LicenseStatus))"
            }) -join ', '
        throw "Multiple Windows licensing products found and none can be selected unambiguously: $summary. Remove duplicate product registrations or specify an activation ID."
    }

    if ($PSCmdlet.ParameterSetName -eq 'DefaultRead')
    {
        $addOns = @($candidates | Where-Object { $_.LicenseIsAddon -eq $true })
        return (@($selectedProduct) + $addOns) | Sort-Object ApplicationID, Name, ID
    }

    return $selectedProduct
}
