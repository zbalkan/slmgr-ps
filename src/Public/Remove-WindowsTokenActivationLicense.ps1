#Requires -Version 5

<#
.SYNOPSIS
Removes an installed token-based activation issuance license.
.DESCRIPTION
Removes the exact issuance license identified by ILID and ILVID through the documented
SoftwareLicensingTokenActivationLicense.Uninstall method and verifies that the license
is no longer returned by the provider.
.INPUTS
String[]. You can pass computer names through the pipeline.
.OUTPUTS
slmgr-ps.LicensingOperationResult. One result is emitted for each attempted computer.
.EXAMPLE
Remove-WindowsTokenActivationLicense -ILID 11111111-2222-3333-4444-555555555555 -ILVID 7
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Remove-WindowsTokenActivationLicense
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
        [Guid]$ILID,

        [Parameter(Mandatory)]
        [uint32]$ILVID
    )

    begin
    {
        $failures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $operation = 'RemoveTokenActivationLicense'
    }

    process
    {
        foreach ($c in $Computer)
        {
            if (-not $PSCmdlet.ShouldProcess($c, "Remove token activation issuance license $ILID version $ILVID"))
            {
                continue
            }

            $session = $null
            try
            {
                $session = Get-Session -Computer $c -Credentials $Credentials -ErrorAction Stop
                $existingLicenses = @(Get-TokenActivationLicense -CimSession $session -ILID $ILID -ILVID $ILVID -ErrorAction Stop)
                if ($existingLicenses.Count -eq 0)
                {
                    throw "Token activation issuance license with ILID $ILID and ILVID $ILVID was not found."
                }

                $license = $existingLicenses[0]
                $license | Invoke-SppCimMethod -MethodName Uninstall

                $remaining = @(Get-TokenActivationLicense -CimSession $session -ILID $ILID -ILVID $ILVID -ErrorAction Stop)
                if ($remaining.Count -ne 0)
                {
                    throw "Token activation issuance license with ILID $ILID and ILVID $ILVID remains installed after the provider accepted removal."
                }

                New-LicensingOperationResult `
                    -ComputerName $c `
                    -Operation $operation `
                    -Success $true `
                    -VerificationState Verified
            }
            catch
            {
                $structured = New-LicensingOperationError `
                    -ErrorRecord $_ `
                    -ComputerName $c `
                    -Operation $operation
                $structured.ErrorRecord.Exception.Data['ILID'] = $ILID.ToString()
                $structured.ErrorRecord.Exception.Data['ILVID'] = $ILVID
                $failures.Add($structured.ErrorRecord)
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
        Complete-LicensingOperationBatch -Failures $failures
    }
}
