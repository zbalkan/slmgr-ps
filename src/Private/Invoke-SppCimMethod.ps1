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
        $methodClasses = @{
            Activate                               = @('SoftwareLicensingProduct')
            ClearKeyManagementServiceMachine       = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
            ClearKeyManagementServicePort          = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
            ClearProductKeyFromRegistry            = @('SoftwareLicensingService')
            DepositOfflineConfirmationId           = @('SoftwareLicensingProduct')
            DisableKeyManagementServiceHostCaching = @('SoftwareLicensingService')
            InstallProductKey                      = @('SoftwareLicensingService')
            ReArmWindows                           = @('SoftwareLicensingService')
            RefreshLicenseStatus                   = @('SoftwareLicensingService')
            SetKeyManagementServiceMachine         = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
            SetKeyManagementServicePort            = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
            UninstallProductKey                    = @('SoftwareLicensingProduct')
        }

        $className = $InputObject.CimClass.CimClassName
        $allowedClasses = $methodClasses[$MethodName]

        if ($null -ne $allowedClasses -and $className -notin $allowedClasses)
        {
            throw "$MethodName requires $($allowedClasses -join ' or '), but received $className"
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
