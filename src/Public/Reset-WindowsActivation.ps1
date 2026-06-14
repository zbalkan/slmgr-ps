#Requires -RunAsAdministrator
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
        $ClearKMSSettings
    )
    Begin
    {
        $PreviousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        Write-Verbose 'ErrorActionPreference: Stop'

        if (-not $UninstallProductKey.IsPresent -and -not $ClearProductKeyFromRegistry.IsPresent -and -not $ClearKMSSettings.IsPresent)
        {
            throw 'At least one reset operation must be specified: -UninstallProductKey, -ClearProductKeyFromRegistry, or -ClearKMSSettings.'
        }
    }
    Process
    {
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
                $session = Get-Session -Computer $c -Credentials $Credentials

                if ($UninstallProductKey.IsPresent -or $ClearProductKeyFromRegistry.IsPresent)
                {
                    $product = Get-WindowsLicensingProduct -CimSession $session

                    if ($UninstallProductKey.IsPresent)
                    {
                        Write-Verbose 'Uninstalling product key (slmgr /upk)'
                        $product | Invoke-SppCimMethod -MethodName UninstallProductKey
                    }

                    if ($ClearProductKeyFromRegistry.IsPresent)
                    {
                        Write-Verbose 'Clearing product key from registry (slmgr /cpky)'
                        $product | Invoke-SppCimMethod -MethodName ClearProductKeyFromRegistry
                    }
                }

                if ($ClearKMSSettings.IsPresent)
                {
                    Write-Verbose 'Clearing KMS settings (slmgr /ckms)'
                    $service = Get-CimInstance -CimSession $session -ClassName SoftwareLicensingService
                    $service | Invoke-SppCimMethod -MethodName ClearKeyManagementServiceMachine
                }
            }
            catch
            {
                throw
            }
            finally
            {
                if ($null -ne $session)
                {
                    Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
                }
            }
        }
    }
    End
    {
        $ErrorActionPreference = $PreviousPreference
    }
}
