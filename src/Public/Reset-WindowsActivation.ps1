#Requires -Version 5

<#
.Synopsis
Resets Windows activation settings.
.DESCRIPTION
A drop in replacement for slmgr /upk, /cpky and /ckms commands. Uninstalls the product key,
clears it from the registry, and/or clears KMS settings. Multiple switches can be combined
in a single call.
.INPUTS
string[]. You can pass the computer names.
.OUTPUTS
None if successful. Throws on error.
.EXAMPLE
Reset-WindowsActivation -UninstallProductKey -Verbose
.EXAMPLE
Reset-WindowsActivation -UninstallProductKey -ClearProductKeyFromRegistry -Verbose
.EXAMPLE
Reset-WindowsActivation -ClearKMSSettings -Verbose
.EXAMPLE
Reset-WindowsActivation -UninstallProductKey -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
.EXAMPLE
Reset-WindowsActivation -Computer WS01 -Credentials (Get-Credential) -UninstallProductKey -ClearProductKeyFromRegistry -ClearKMSSettings
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Reset-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High')]
    Param
    (
        # Type localhost or . for local computer or do not use the parameter
        [Parameter(Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [AllowNull()]
        [string[]]
        $Computer = @('localhost'),

        # Define credentials other than current user if needed
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [AllowNull()]
        [PSCredential]
        $Credentials,

        # Uninstall the product key (slmgr /upk)
        [Parameter(Mandatory = $false)]
        [switch]
        $UninstallProductKey,

        # Clear the product key from the registry (slmgr /cpky)
        [Parameter(Mandatory = $false)]
        [switch]
        $ClearProductKeyFromRegistry,

        # Clear KMS settings (slmgr /ckms)
        [Parameter(Mandatory = $false)]
        [switch]
        $ClearKMSSettings,

        [Parameter(Mandatory = $false)]
        [Guid]
        $ActivationId
    )
    Begin
    {
        if (-not $UninstallProductKey.IsPresent -and -not $ClearProductKeyFromRegistry.IsPresent -and -not $ClearKMSSettings.IsPresent)
        {
            throw 'At least one reset operation must be specified: -UninstallProductKey, -ClearProductKeyFromRegistry, or -ClearKMSSettings.'
        }
        $hasActivationId = $PSBoundParameters.ContainsKey('ActivationId')
        $hasTargetedOperation = $UninstallProductKey.IsPresent -or $ClearKMSSettings.IsPresent
        if ($hasActivationId -and -not $hasTargetedOperation)
        {
            throw 'ActivationId requires UninstallProductKey or ClearKMSSettings.'
        }
    }
    Process
    {
        $resetFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        Write-Verbose "Enumerating computers: $($Computer.Count) computer(s)."
        foreach ($c in $Computer)
        {
            if (-not $PSCmdlet.ShouldProcess($c, 'Reset Windows activation settings'))
            {
                continue
            }

            Write-Verbose "Creating new CimSession for computer $c"
            $session = $null
            try
            {
                $session = Get-Session -Computer $c -Credentials $Credentials -ErrorAction Stop

                $product = $null
                if ($PSBoundParameters.ContainsKey('ActivationId'))
                {
                    $product = Get-WindowsLicensingProduct -CimSession $session -ActivationId $ActivationId
                }

                if ($UninstallProductKey.IsPresent)
                {
                    if ($null -eq $product) { $product = Get-WindowsLicensingProduct -CimSession $session }

                    Write-Verbose 'Uninstalling product key (slmgr /upk)'
                    $product | Invoke-SppCimMethod -MethodName UninstallProductKey
                }

                $requiresService = $ClearProductKeyFromRegistry.IsPresent
                if ($ClearKMSSettings.IsPresent -and $null -eq $product) { $requiresService = $true }
                if ($requiresService)
                {
                    $service = Get-CimInstance -CimSession $session -ClassName SoftwareLicensingService -ErrorAction Stop
                }

                if ($ClearProductKeyFromRegistry.IsPresent)
                {
                    Write-Verbose 'Clearing product key from registry (slmgr /cpky)'
                    $service | Invoke-SppCimMethod -MethodName ClearProductKeyFromRegistry
                }

                if ($ClearKMSSettings.IsPresent)
                {
                    Write-Verbose 'Clearing KMS settings (slmgr /ckms)'
                    $kmsTarget = if ($null -ne $product) { $product } else { $service }
                    $kmsTarget | Invoke-SppCimMethod -MethodName ClearKeyManagementServiceMachine
                    $kmsTarget | Invoke-SppCimMethod -MethodName ClearKeyManagementServicePort
                }
            }
            catch
            {
                $resetFailures.Add($_)
            }
            finally
            {
                if ($null -ne $session)
                {
                    Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
                }
            }
        }

        if ($resetFailures.Count -gt 0)
        {
            foreach ($failure in $resetFailures)
            {
                Write-Error -ErrorRecord $failure
            }
            $PSCmdlet.ThrowTerminatingError($resetFailures[0])
        }
    }
}
