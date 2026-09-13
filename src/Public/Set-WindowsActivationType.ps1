#Requires -Version 5

<#
.SYNOPSIS
Configures the permitted Windows volume activation type.
.DESCRIPTION
Limits volume activation to Active Directory, KMS, or token-based activation, or
clears the restriction so any supported activation type can be used. The setting can
be applied service-wide or to an exact licensing product with ActivationId.
.INPUTS
String[]. You can pass computer names through the pipeline.
.OUTPUTS
slmgr-ps.LicensingOperationResult. One result is emitted for each attempted computer.
Throws one aggregate error after processing the requested computer batch when any
computer fails.
.EXAMPLE
Set-WindowsActivationType -ActivationType Kms
.EXAMPLE
Set-WindowsActivationType -ActivationType ActiveDirectory
.EXAMPLE
Set-WindowsActivationType -ActivationType Token
.EXAMPLE
Set-WindowsActivationType -ActivationType Any
.EXAMPLE
Set-WindowsActivationType -ActivationType Kms -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Set-WindowsActivationType
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High')]
    param(
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [AllowNull()]
        [string[]]$Computer = @('localhost'),

        [Parameter()]
        [AllowNull()]
        [PSCredential]$Credentials,

        [Parameter(Mandatory)]
        [ValidateSet('Any', 'ActiveDirectory', 'Kms', 'Token')]
        [string]$ActivationType,

        [Parameter()]
        [Guid]$ActivationId
    )

    begin
    {
        $hasActivationId = $PSBoundParameters.ContainsKey('ActivationId')
        $resultActivationId = if ($hasActivationId) { $ActivationId } else { $null }
        $policyFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $operation = 'SetActivationType'

        $activationTypeValue = switch ($ActivationType)
        {
            'ActiveDirectory' { 1 }
            'Kms' { 2 }
            'Token' { 3 }
            default { 0 }
        }
    }

    process
    {
        foreach ($c in $Computer)
        {
            $action = if ($ActivationType -eq 'Any')
            {
                'Allow any supported volume activation type'
            }
            else
            {
                "Limit volume activation to $ActivationType"
            }

            if (-not $PSCmdlet.ShouldProcess($c, $action))
            {
                continue
            }

            $session = $null
            $target = $null
            try
            {
                $session = Get-Session -Computer $c -Credentials $Credentials -ErrorAction Stop
                if ($hasActivationId)
                {
                    $target = Get-WindowsLicensingProduct -CimSession $session `
                        -ActivationId $ActivationId -ErrorAction Stop
                }
                else
                {
                    $target = Get-CimInstance -CimSession $session `
                        -ClassName SoftwareLicensingService -ErrorAction Stop
                }

                if ($activationTypeValue -eq 0)
                {
                    $target | Invoke-SppCimMethod -MethodName ClearVLActivationTypeEnabled
                }
                else
                {
                    $target | Invoke-SppCimMethod -MethodName SetVLActivationTypeEnabled `
                        -Arguments @{ ActivationType = $activationTypeValue }
                }

                $productName = if ($hasActivationId) { $target.Name } else { $null }
                New-LicensingOperationResult `
                    -ComputerName $c `
                    -Operation $operation `
                    -Success $true `
                    -ActivationId $resultActivationId `
                    -ProductName $productName `
                    -VerificationState ProviderAccepted
            }
            catch
            {
                $productName = if ($hasActivationId -and $null -ne $target) { $target.Name } else { $null }
                $structured = New-LicensingOperationError `
                    -ErrorRecord $_ `
                    -ComputerName $c `
                    -Operation $operation `
                    -ActivationId $resultActivationId `
                    -ProductName $productName
                $policyFailures.Add($structured.ErrorRecord)
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

    end
    {
        Complete-LicensingOperationBatch -Failures $policyFailures
    }
}
