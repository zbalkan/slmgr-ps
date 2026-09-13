function New-LicensingOperationResult
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Operation,

        [Parameter(Mandatory)]
        [bool]$Success,

        [AllowNull()]
        [object]$ActivationId,

        [AllowNull()]
        [string]$ProductName,

        [bool]$RestartRequired = $false,

        [AllowNull()]
        [string]$ErrorCode,

        [AllowNull()]
        [string]$ErrorMessage,

        [Parameter(Mandatory)]
        [ValidateSet('Verified', 'ProviderAccepted', 'NotVerifiable', 'Failed')]
        [string]$VerificationState
    )

    $result = [PSCustomObject]@{
        ComputerName      = $ComputerName
        Success           = $Success
        Operation         = $Operation
        ActivationId      = $ActivationId
        ProductName       = $ProductName
        RestartRequired   = $RestartRequired
        ErrorCode         = $ErrorCode
        ErrorMessage      = $ErrorMessage
        VerificationState = $VerificationState
    }
    $result.PSObject.TypeNames.Insert(0, 'slmgr-ps.LicensingOperationResult')
    return $result
}
