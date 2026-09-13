function Get-ADActivationObjectRecord
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [string]$Name,
        [string]$DistinguishedName,
        [string]$Server,
        [PSCredential]$Credential
    )

    $common = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $common['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $common['Credential'] = $Credential }

    $properties = @(
        'msSPP-CSVLKPid',
        'msSPP-CSVLKSkuId',
        'msSPP-CSVLKPartialProductKey',
        'msSPP-KMSIds'
    )

    if (-not [string]::IsNullOrWhiteSpace($DistinguishedName))
    {
        $candidates = @(Get-ADObject @common -Identity $DistinguishedName -Properties $properties -ErrorAction Stop)
    }
    else
    {
        $candidates = @(Get-ADObject @common -LDAPFilter '(objectClass=msSPP-ActivationObject)' -SearchBase $Context.ContainerDistinguishedName -SearchScope OneLevel -Properties $properties -ErrorAction Stop)
        if (-not [string]::IsNullOrWhiteSpace($Name))
        {
            $candidates = @($candidates | Where-Object { $_.Name -ceq $Name })
        }
    }

    foreach ($candidate in $candidates)
    {
        if ($candidate.ObjectClass -ne 'msSPP-ActivationObject')
        {
            throw "Active Directory object '$($candidate.DistinguishedName)' is not an msSPP-ActivationObject."
        }

        [PSCustomObject]@{
            Forest                 = $Context.Forest
            Domain                 = $Context.Domain
            Name                   = $candidate.Name
            DistinguishedName      = $candidate.DistinguishedName
            ObjectGuid             = $candidate.ObjectGuid
            CsvlkPid               = $candidate.'msSPP-CSVLKPid'
            CsvlkSkuId             = $candidate.'msSPP-CSVLKSkuId'
            CsvlkPartialProductKey = $candidate.'msSPP-CSVLKPartialProductKey'
            KmsIds                 = $candidate.'msSPP-KMSIds'
        }
    }
}
