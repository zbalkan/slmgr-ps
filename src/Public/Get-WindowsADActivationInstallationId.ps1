#Requires -Version 5

function Get-WindowsADActivationInstallationId
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)]
        [string]$ProductKey
    )

    $segments = @($ProductKey -split '-')
    $invalidSegments = @($segments | Where-Object { $_.Length -ne 5 -or $_ -notmatch '^[A-Za-z0-9]+$' })
    if ($segments.Count -ne 5 -or $invalidSegments.Count -ne 0)
    {
        throw 'ProductKey must contain five groups of five alphanumeric characters.'
    }

    $service = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
    $providerResult = $service | Invoke-SppCimMethod -MethodName GenerateActiveDirectoryOfflineActivationId -Arguments @{ ProductKey = $ProductKey } -PassThru

    if ([string]::IsNullOrWhiteSpace($providerResult.InstallationID))
    {
        throw 'The Software Protection Platform did not return an Active Directory activation installation ID.'
    }

    $result = [PSCustomObject]@{
        InstallationId = $providerResult.InstallationID
    }
    $result.PSObject.TypeNames.Insert(0, 'slmgr-ps.ADActivationInstallationId')
    return $result
}
