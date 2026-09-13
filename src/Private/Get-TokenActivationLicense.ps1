function Get-TokenActivationLicense
{
    [OutputType([CimInstance])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,

        [Guid]$ILID,

        [uint32]$ILVID
    )

    $properties = (Get-SppContract).TokenActivationLicenseProperties
    $query = "SELECT $($properties -join ', ') FROM SoftwareLicensingTokenActivationLicense"

    $hasIlid = $PSBoundParameters.ContainsKey('ILID')
    $hasIlvid = $PSBoundParameters.ContainsKey('ILVID')
    if ($hasIlid -xor $hasIlvid)
    {
        throw 'ILID and ILVID must be specified together.'
    }

    if ($hasIlid)
    {
        $query += " WHERE ILID = '$($ILID.ToString())' AND ILVID = $ILVID"
    }

    $licenses = @(Get-CimInstance -CimSession $CimSession -Query $query -ErrorAction Stop)

    if ($hasIlid)
    {
        if ($licenses.Count -eq 0)
        {
            return @()
        }
        if ($licenses.Count -ne 1)
        {
            throw "Multiple token activation issuance licenses matched ILID $ILID and ILVID $ILVID."
        }
        return $licenses[0]
    }

    return $licenses | Sort-Object ILID, ILVID, ID
}
