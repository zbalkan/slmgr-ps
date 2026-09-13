function Complete-LicensingOperationBatch
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]$Failures
    )

    if ($Failures.Count -eq 0)
    {
        return
    }

    $innerExceptions = [System.Collections.Generic.List[System.Exception]]::new()
    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($failure in $Failures)
    {
        $innerExceptions.Add($failure.Exception)
        $targets.Add($failure.TargetObject)
    }

    $firstFailure = $Failures[0].Exception.InnerException
    if ($null -eq $firstFailure) { $firstFailure = $Failures[0].Exception }
    $message = "$($Failures.Count) licensing operation(s) failed. First failure: $($firstFailure.Message)"
    $exception = [System.AggregateException]::new($message, $innerExceptions.ToArray())
    $exception.Data['Failures'] = $Failures.ToArray()

    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
        $exception,
        'LicensingBatchFailed',
        [System.Management.Automation.ErrorCategory]::OperationStopped,
        $targets.ToArray())
    $PSCmdlet.ThrowTerminatingError($errorRecord)
}
