#Requires -Version 5

function New-WindowsADActivationObject
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Online', PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)]
        [string]$ProductKey,

        [Parameter(Mandatory)]
        [ValidateLength(1, 40)]
        [ValidateScript({ $_ -notmatch '[,=+<>#;"\\\x00-\x1F]' })]
        [string]$ActivationObjectName,

        [Parameter(Mandatory, ParameterSetName = 'Offline')]
        [ValidateNotNullOrEmpty()]
        [string]$ConfirmationId,

        [string]$DirectoryServer,
        [PSCredential]$DirectoryCredential
    )

    $segments = @($ProductKey -split '-')
    $invalidSegments = @($segments | Where-Object { $_.Length -ne 5 -or $_ -notmatch '^[A-Za-z0-9]+$' })
    if ($segments.Count -ne 5 -or $invalidSegments.Count -ne 0)
    {
        throw 'ProductKey must contain five groups of five alphanumeric characters.'
    }

    $contextParams = @{}
    if ($PSBoundParameters.ContainsKey('DirectoryServer')) { $contextParams['Server'] = $DirectoryServer }
    if ($PSBoundParameters.ContainsKey('DirectoryCredential')) { $contextParams['Credential'] = $DirectoryCredential }
    $context = Get-ADActivationContext @contextParams

    $lookupParams = @{ Context = $context; Name = $ActivationObjectName }
    if ($PSBoundParameters.ContainsKey('DirectoryServer')) { $lookupParams['Server'] = $DirectoryServer }
    if ($PSBoundParameters.ContainsKey('DirectoryCredential')) { $lookupParams['Credential'] = $DirectoryCredential }
    if (@(Get-ADActivationObjectRecord @lookupParams).Count -ne 0)
    {
        throw "An Active Directory activation object named '$ActivationObjectName' already exists."
    }

    if (-not $PSCmdlet.ShouldProcess($context.Forest, "Create Active Directory activation object '$ActivationObjectName'"))
    {
        return
    }

    $service = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
    if ($PSCmdlet.ParameterSetName -eq 'Offline')
    {
        $service | Invoke-SppCimMethod -MethodName DepositActiveDirectoryOfflineActivationConfirmation -Arguments @{
            ProductKey = $ProductKey
            ConfirmationID = $ConfirmationId
            ActivationObjectName = $ActivationObjectName
        }
    }
    else
    {
        $service | Invoke-SppCimMethod -MethodName DoActiveDirectoryOnlineActivation -Arguments @{
            ProductKey = $ProductKey
            ActivationObjectName = $ActivationObjectName
        }
    }

    $created = @(Get-ADActivationObjectRecord @lookupParams)
    if ($created.Count -ne 1)
    {
        throw "Active Directory activation object '$ActivationObjectName' could not be verified after creation."
    }

    $result = New-LicensingOperationResult -ComputerName 'localhost' -Operation 'CreateADActivationObject' -Success $true -VerificationState Verified
    Add-Member -InputObject $result -NotePropertyName Forest -NotePropertyValue $context.Forest
    Add-Member -InputObject $result -NotePropertyName Domain -NotePropertyValue $context.Domain
    Add-Member -InputObject $result -NotePropertyName ActivationObjectName -NotePropertyValue $created[0].Name
    Add-Member -InputObject $result -NotePropertyName DistinguishedName -NotePropertyValue $created[0].DistinguishedName
    return $result
}
