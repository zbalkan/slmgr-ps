function New-LicensingOperationError
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Operation,

        [AllowNull()]
        [object]$ActivationId,

        [AllowNull()]
        [string]$ProductName,

        [bool]$RestartRequired = $false
    )

    $errorCode = $null
    if ($null -ne $ErrorRecord.Exception -and
        $null -ne $ErrorRecord.Exception.Data -and
        $ErrorRecord.Exception.Data.Contains('ErrorCode'))
    {
        $errorCode = [string]$ErrorRecord.Exception.Data['ErrorCode']
    }
    elseif ($null -ne $ErrorRecord.Exception -and $ErrorRecord.Exception.HResult -ne 0)
    {
        $unsignedHResult = [BitConverter]::ToUInt32(
            [BitConverter]::GetBytes([int]$ErrorRecord.Exception.HResult), 0)
        $errorCode = '0x{0:X8}' -f $unsignedHResult
    }

    $result = New-LicensingOperationResult `
        -ComputerName $ComputerName `
        -Operation $Operation `
        -Success $false `
        -ActivationId $ActivationId `
        -ProductName $ProductName `
        -RestartRequired $RestartRequired `
        -ErrorCode $errorCode `
        -ErrorMessage $ErrorRecord.Exception.Message `
        -VerificationState Failed

    $message = "$Operation failed on '$ComputerName': $($ErrorRecord.Exception.Message)"
    $exception = [System.InvalidOperationException]::new($message, $ErrorRecord.Exception)
    $exception.Data['ComputerName'] = $ComputerName
    $exception.Data['Operation'] = $Operation
    if ($null -ne $errorCode) { $exception.Data['ErrorCode'] = $errorCode }
    if ($null -ne $ActivationId) { $exception.Data['ActivationId'] = $ActivationId }
    if (-not [string]::IsNullOrEmpty($ProductName)) { $exception.Data['ProductName'] = $ProductName }
    $exception.Data['OriginalErrorRecord'] = $ErrorRecord

    $structuredError = [System.Management.Automation.ErrorRecord]::new(
        $exception,
        'LicensingOperationFailed',
        $ErrorRecord.CategoryInfo.Category,
        $result)

    [PSCustomObject]@{
        Result      = $result
        ErrorRecord = $structuredError
    }
}
