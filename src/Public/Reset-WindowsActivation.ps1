#Requires -Version 5

<#
.Synopsis
Resets Windows activation settings.
.DESCRIPTION
A drop in replacement for slmgr /upk, /cpky, /ckms, and /ckms-domain commands. Uninstalls the product key,
clears it from the registry, clears KMS host and port settings, and/or clears the KMS
lookup domain. Multiple switches can be combined in a single call.
.INPUTS
string[]. You can pass the computer names.
.OUTPUTS
slmgr-ps.LicensingOperationResult. One result is emitted for each attempted computer.
Throws one aggregate error after processing the requested computer batch when any
computer fails.
.EXAMPLE
Reset-WindowsActivation -UninstallProductKey -Verbose
.EXAMPLE
Reset-WindowsActivation -UninstallProductKey -ClearProductKeyFromRegistry -Verbose
.EXAMPLE
Reset-WindowsActivation -ClearKMSSettings -Verbose
.EXAMPLE
Reset-WindowsActivation -ClearKMSLookupDomain -Verbose
.EXAMPLE
Reset-WindowsActivation -UninstallProductKey -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
.EXAMPLE
Reset-WindowsActivation -Computer WS01 -Credentials (Get-Credential) -UninstallProductKey -ClearProductKeyFromRegistry -ClearKMSSettings
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Reset-WindowsActivation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High')]
    Param
    (
        [Parameter(Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [AllowNull()]
        [string[]]
        $Computer = @('localhost'),

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [AllowNull()]
        [PSCredential]
        $Credentials,

        [Parameter(Mandatory = $false)]
        [switch]
        $UninstallProductKey,

        [Parameter(Mandatory = $false)]
        [switch]
        $ClearProductKeyFromRegistry,

        [Parameter(Mandatory = $false)]
        [switch]
        $ClearKMSSettings,

        [Parameter(Mandatory = $false)]
        [switch]
        $ClearKMSLookupDomain,

        [Parameter(Mandatory = $false)]
        [Guid]
        $ActivationId
    )
    Begin
    {
        if (-not $UninstallProductKey.IsPresent -and
            -not $ClearProductKeyFromRegistry.IsPresent -and
            -not $ClearKMSSettings.IsPresent -and
            -not $ClearKMSLookupDomain.IsPresent)
        {
            throw 'At least one reset operation must be specified: -UninstallProductKey, -ClearProductKeyFromRegistry, -ClearKMSSettings, or -ClearKMSLookupDomain.'
        }
        $hasActivationId = $PSBoundParameters.ContainsKey('ActivationId')
        $hasTargetedOperation = $UninstallProductKey.IsPresent -or
            $ClearKMSSettings.IsPresent -or $ClearKMSLookupDomain.IsPresent
        if ($hasActivationId -and -not $hasTargetedOperation)
        {
            throw 'ActivationId requires UninstallProductKey, ClearKMSSettings, or ClearKMSLookupDomain.'
        }

        $resultActivationId = if ($hasActivationId) { $ActivationId } else { $null }
        $resetFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
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
            $product = $null
            try
            {
                $session = Get-Session -Computer $c -Credentials $Credentials -ErrorAction Stop

                if ($hasActivationId)
                {
                    $product = Get-WindowsLicensingProduct -CimSession $session -ActivationId $ActivationId
                }

                $requiresService = $ClearProductKeyFromRegistry.IsPresent
                if ($ClearKMSSettings.IsPresent -and $null -eq $product) { $requiresService = $true }
                if ($ClearKMSLookupDomain.IsPresent -and $null -eq $product) { $requiresService = $true }
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

                if ($ClearKMSLookupDomain.IsPresent)
                {
                    Write-Verbose 'Clearing KMS lookup domain (slmgr /ckms-domain)'
                    $kmsTarget = if ($null -ne $product) { $product } else { $service }
                    $kmsTarget | Invoke-SppCimMethod -MethodName ClearKeyManagementServiceLookupDomain
                }

                if ($UninstallProductKey.IsPresent)
                {
                    if ($null -eq $product) { $product = Get-WindowsLicensingProduct -CimSession $session }

                    Write-Verbose 'Uninstalling product key (slmgr /upk)'
                    $product | Invoke-SppCimMethod -MethodName UninstallProductKey
                }

                $productName = if ($null -ne $product) { $product.Name } else { $null }
                New-LicensingOperationResult `
                    -ComputerName $c `
                    -Operation ResetActivation `
                    -Success $true `
                    -ActivationId $resultActivationId `
                    -ProductName $productName `
                    -VerificationState ProviderAccepted
            }
            catch
            {
                $productName = if ($null -ne $product) { $product.Name } else { $null }
                $structured = New-LicensingOperationError `
                    -ErrorRecord $_ `
                    -ComputerName $c `
                    -Operation ResetActivation `
                    -ActivationId $resultActivationId `
                    -ProductName $productName
                $resetFailures.Add($structured.ErrorRecord)
                Write-Output $structured.Result
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
        Complete-LicensingOperationBatch -Failures $resetFailures
    }
}
