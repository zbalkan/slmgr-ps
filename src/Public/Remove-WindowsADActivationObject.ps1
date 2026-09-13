#Requires -Version 5

function Remove-WindowsADActivationObject
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName,

        [string]$DirectoryServer,
        [PSCredential]$DirectoryCredential
    )

    $contextParams = @{}
    if ($PSBoundParameters.ContainsKey('DirectoryServer')) { $contextParams['Server'] = $DirectoryServer }
    if ($PSBoundParameters.ContainsKey('DirectoryCredential')) { $contextParams['Credential'] = $DirectoryCredential }
    $context = Get-ADActivationContext @contextParams

    $lookupParams = @{ Context = $context; DistinguishedName = $DistinguishedName }
    if ($PSBoundParameters.ContainsKey('DirectoryServer')) { $lookupParams['Server'] = $DirectoryServer }
    if ($PSBoundParameters.ContainsKey('DirectoryCredential')) { $lookupParams['Credential'] = $DirectoryCredential }
    $target = @(Get-ADActivationObjectRecord @lookupParams)
    if ($target.Count -ne 1)
    {
        throw "Active Directory activation object '$DistinguishedName' could not be resolved unambiguously."
    }

    $resolved = $target[0]
    if (-not $PSCmdlet.ShouldProcess($resolved.DistinguishedName, "Remove Active Directory activation object '$($resolved.Name)'"))
    {
        return
    }

    $removeParams = @{ Identity = $resolved.DistinguishedName; Confirm = $false; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('DirectoryServer')) { $removeParams['Server'] = $DirectoryServer }
    if ($PSBoundParameters.ContainsKey('DirectoryCredential')) { $removeParams['Credential'] = $DirectoryCredential }
    Remove-ADObject @removeParams

    $verifyParams = @{ Context = $context }
    if ($PSBoundParameters.ContainsKey('DirectoryServer')) { $verifyParams['Server'] = $DirectoryServer }
    if ($PSBoundParameters.ContainsKey('DirectoryCredential')) { $verifyParams['Credential'] = $DirectoryCredential }
    $remaining = @(Get-ADActivationObjectRecord @verifyParams | Where-Object { $_.DistinguishedName -eq $resolved.DistinguishedName })
    if ($remaining.Count -ne 0)
    {
        throw "Active Directory activation object '$($resolved.DistinguishedName)' remains after deletion."
    }

    $result = New-LicensingOperationResult -ComputerName 'localhost' -Operation 'RemoveADActivationObject' -Success $true -VerificationState Verified
    Add-Member -InputObject $result -NotePropertyName Forest -NotePropertyValue $context.Forest
    Add-Member -InputObject $result -NotePropertyName Domain -NotePropertyValue $context.Domain
    Add-Member -InputObject $result -NotePropertyName ActivationObjectName -NotePropertyValue $resolved.Name
    Add-Member -InputObject $result -NotePropertyName DistinguishedName -NotePropertyValue $resolved.DistinguishedName
    return $result
}
