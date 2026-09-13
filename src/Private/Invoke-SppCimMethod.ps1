function Invoke-SppCimMethod
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [CimInstance]$InputObject,
        [Parameter(Mandatory)]
        [string]$MethodName,
        [hashtable]$Arguments,
        [switch]$PassThru
    )
    Process
    {
        $methodContract = (Get-SppContract).Methods[$MethodName]
        if ($null -eq $methodContract)
        {
            throw "Unsupported SPP method: $MethodName"
        }

        $className = $InputObject.CimClass.CimClassName
        $allowedClasses = $methodContract.Classes

        if ($className -notin $allowedClasses)
        {
            throw "$MethodName requires $($allowedClasses -join ' or '), but received $className"
        }

        $suppliedArguments = if ($null -eq $Arguments) { @() } else { @($Arguments.Keys) }
        $missingArguments = @($methodContract.Arguments | Where-Object { $_ -notin $suppliedArguments })
        $unexpectedArguments = @($suppliedArguments | Where-Object { $_ -notin $methodContract.Arguments })

        if ($missingArguments.Count -gt 0)
        {
            throw "$MethodName requires argument(s): $($missingArguments -join ', ')"
        }
        if ($unexpectedArguments.Count -gt 0)
        {
            throw "$MethodName does not accept argument(s): $($unexpectedArguments -join ', ')"
        }

        $invokeParams = @{ MethodName = $MethodName }
        if ($PSBoundParameters.ContainsKey('Arguments')) { $invokeParams['Arguments'] = $Arguments }

        $result = $InputObject | Invoke-CimMethod @invokeParams -ErrorAction Stop

        if ($null -ne $result -and $result.ReturnValue -ne 0)
        {
            $returnValue = [uint32]$result.ReturnValue
            $errorCode = '0x{0:X8}' -f $returnValue
            $message = "${MethodName}: licensing operation failed (return value: $returnValue, error code: $errorCode)"
            $exception = [System.InvalidOperationException]::new($message)
            $exception.Data['ProviderReturnValue'] = $returnValue
            $exception.Data['ErrorCode'] = $errorCode
            $exception.Data['MethodName'] = $MethodName
            $target = [PSCustomObject]@{
                MethodName          = $MethodName
                ClassName           = $className
                ProviderReturnValue = $returnValue
                ErrorCode           = $errorCode
            }
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $exception,
                'SppProviderMethodFailed',
                [System.Management.Automation.ErrorCategory]::InvalidResult,
                $target)
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        if ($PassThru.IsPresent)
        {
            return $result
        }
    }
}
