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
    $candidateException = $ErrorRecord.Exception
    $cimException = $null
    while ($null -ne $candidateException -and $null -eq $errorCode)
    {
        if ($null -ne $candidateException.Data -and $candidateException.Data.Contains('ErrorCode'))
        {
            $errorCode = [string]$candidateException.Data['ErrorCode']
            break
        }

        if ($null -eq $cimException -and
            $candidateException -is [Microsoft.Management.Infrastructure.CimException])
        {
            $cimException = $candidateException
        }

        if ($candidateException -is [System.AggregateException] -and
            $candidateException.InnerExceptions.Count -gt 0)
        {
            $candidateException = $candidateException.InnerExceptions[0]
        }
        else
        {
            $candidateException = $candidateException.InnerException
        }
    }

    if ($null -eq $errorCode -and $null -ne $cimException -and $cimException.HResult -ne 0)
    {
        $unsignedHResult = [BitConverter]::ToUInt32(
            [BitConverter]::GetBytes([int]$cimException.HResult), 0)
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
