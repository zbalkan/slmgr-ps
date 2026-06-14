function Invoke-SppCimMethod
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [CimInstance]$InputObject,
        [Parameter(Mandatory)]
        [string]$MethodName,
        [hashtable]$Arguments
    )
    Process
    {
        $invokeParams = @{ MethodName = $MethodName }
        if ($PSBoundParameters.ContainsKey('Arguments')) { $invokeParams['Arguments'] = $Arguments }

        $result = $InputObject | Invoke-CimMethod @invokeParams -ErrorAction Stop

        if ($null -ne $result -and $result.ReturnValue -ne 0)
        {
            throw "${MethodName}: licensing operation failed (return value: $($result.ReturnValue))"
        }
    }
}
