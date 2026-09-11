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
        $serviceMethods = @(
            'ClearKeyManagementServiceMachine',
            'ClearKeyManagementServicePort',
            'ClearProductKeyFromRegistry',
            'DisableKeyManagementServiceHostCaching',
            'InstallProductKey',
            'ReArmWindows',
            'RefreshLicenseStatus',
            'SetKeyManagementServiceMachine',
            'SetKeyManagementServicePort'
        )
        $productMethods = @(
            'Activate',
            'DepositOfflineConfirmationId',
            'UninstallProductKey'
        )

        $className = $InputObject.CimClass.CimClassName
        $expectedClass = if ($MethodName -in $serviceMethods)
        {
            'SoftwareLicensingService'
        }
        elseif ($MethodName -in $productMethods)
        {
            'SoftwareLicensingProduct'
        }

        if ($null -ne $expectedClass -and $className -ne $expectedClass)
        {
            throw "$MethodName requires $expectedClass, but received $className"
        }

        $invokeParams = @{ MethodName = $MethodName }
        if ($PSBoundParameters.ContainsKey('Arguments')) { $invokeParams['Arguments'] = $Arguments }

        $result = $InputObject | Invoke-CimMethod @invokeParams -ErrorAction Stop

        if ($null -ne $result -and $result.ReturnValue -ne 0)
        {
            throw "${MethodName}: licensing operation failed (return value: $($result.ReturnValue))"
        }
    }
}
