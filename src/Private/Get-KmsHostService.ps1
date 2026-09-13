function Get-KmsHostService
{
    [OutputType([CimInstance])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    $service = Get-CimInstance -CimSession $CimSession -ClassName SoftwareLicensingService -ErrorAction Stop
    if ([uint32]$service.IsKeyManagementServiceMachine -ne 1)
    {
        throw 'The target is not enabled as a Key Management Service host.'
    }

    return $service
}
