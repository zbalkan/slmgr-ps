#Requires -Version 5

function Get-WindowsADActivationObject
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [string]$Name,
        [string]$DistinguishedName,
        [string]$DirectoryServer,
        [PSCredential]$DirectoryCredential
    )

    if ($PSBoundParameters.ContainsKey('Name') -and $PSBoundParameters.ContainsKey('DistinguishedName'))
    {
        throw 'Specify either Name or DistinguishedName, not both.'
    }

    $contextParams = @{}
    if ($PSBoundParameters.ContainsKey('DirectoryServer')) { $contextParams['Server'] = $DirectoryServer }
    if ($PSBoundParameters.ContainsKey('DirectoryCredential')) { $contextParams['Credential'] = $DirectoryCredential }
    $context = Get-ADActivationContext @contextParams

    $lookupParams = @{ Context = $context }
    if ($PSBoundParameters.ContainsKey('Name')) { $lookupParams['Name'] = $Name }
    if ($PSBoundParameters.ContainsKey('DistinguishedName')) { $lookupParams['DistinguishedName'] = $DistinguishedName }
    if ($PSBoundParameters.ContainsKey('DirectoryServer')) { $lookupParams['Server'] = $DirectoryServer }
    if ($PSBoundParameters.ContainsKey('DirectoryCredential')) { $lookupParams['Credential'] = $DirectoryCredential }

    Get-ADActivationObjectRecord @lookupParams
}
