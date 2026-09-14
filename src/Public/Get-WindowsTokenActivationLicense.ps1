#Requires -Version 5

<#
.SYNOPSIS
Lists installed token-based activation issuance licenses.
.DESCRIPTION
Returns structured information from the documented
SoftwareLicensingTokenActivationLicense provider class.
.INPUTS
String[]. You can pass computer names through the pipeline.
.OUTPUTS
slmgr-ps.TokenActivationLicense.
.EXAMPLE
Get-WindowsTokenActivationLicense
.EXAMPLE
Get-WindowsTokenActivationLicense -Computer WS01
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Get-WindowsTokenActivationLicense
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [AllowNull()]
        [string[]]$Computer = @('localhost'),

        [Parameter()]
        [AllowNull()]
        [PSCredential]$Credentials
    )

    process
    {
        foreach ($c in $Computer)
        {
            $session = $null
            try
            {
                $session = Get-Session -Computer $c -Credentials $Credentials -ErrorAction Stop
                $licenses = @(Get-TokenActivationLicense -CimSession $session -ErrorAction Stop)
                foreach ($license in $licenses)
                {
                    $expirationDate = $license.ExpirationDate
                    if ($null -eq $expirationDate -or $expirationDate -eq [datetime]::MinValue)
                    {
                        $expirationDate = $null
                    }

                    $authorizationStatusCode = [uint32]$license.AuthorizationStatus
                    $result = [PSCustomObject][ordered]@{
                        ComputerName            = $c
                        ID                      = $license.ID
                        ILID                    = $license.ILID
                        ILVID                   = [uint32]$license.ILVID
                        AuthorizationStatusCode = $authorizationStatusCode
                        AuthorizationStatus     = '0x{0:X8}' -f $authorizationStatusCode
                        ExpirationDate          = $expirationDate
                        Description             = $license.Description
                        AdditionalInfo          = $license.AdditionalInfo
                    }
                    $result.PSObject.TypeNames.Insert(0, 'slmgr-ps.TokenActivationLicense')
                    Write-Output $result
                }
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
}
