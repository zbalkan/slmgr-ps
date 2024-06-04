#Requires -RunAsAdministrator
#Requires -Version 5

<#
.Synopsis
Activates Windows via KMS
.DESCRIPTION
A drop in replacement for slmgr script
.INPUTS
string[]. You can pass the computer names
.OUTPUTS
None if successful. Error message if there is an error.
.EXAMPLE
Start-WindowsActivation -Verbose # Activates the local computer
.EXAMPLE
Start-WindowsActivation -Computer WS01 -Credentials (Get-Credential) # Activates the computer named WS01 using different credentials
.EXAMPLE
Start-WindowsActivation -Computer WS01, WS02 -CacheDisabled $false # Disabled the KMS cache for the computers named WS01 and WS02. Cache is enabled by default.
.EXAMPLE
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500 # Activates the computer named WS01 against server.domain.net:2500
.EXAMPLE
Start-WindowsActivation -ReArm # ReArm the trial period. ReArming already licensed devices can break current license issues. Guard clauses wil protect 99% but cannot guarantee 100%.
.EXAMPLE
Start-WindowsActivation -Offline -ConfirmationID <confirmation ID> # Used for offline -aka phone- activation
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Start-WindowsActivation
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'ActivateWithKMS')]
    Param
    (
        # Type localhost or . for local computer or do not use the parameter
        [Parameter(Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'ActivateWithKMS')]
        [Parameter(ParameterSetName = 'Rearm')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [string[]]
        $Computer = @('localhost'),

        # Define credentials other than current user if needed
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'ActivateWithKMS')]
        [Parameter(ParameterSetName = 'Rearm')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [PSCredential]
        $Credentials,

        [Parameter(Mandatory = $false,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ActivateWithKMS')]
        [ValidateLength(6, 253)]
        [ValidateScript(
            {
                $pattern = [Regex]::new('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)')
                if ($pattern.Matches($_).Count -gt 0)
                {
                    $true
                }
                else
                {
                    throw "$_ is invalid. Please provide a valid FQDN"
                }
            })]
        [ValidateNotNullOrEmpty()]
        [string]
        $KMSServerFQDN,

        [Parameter(Mandatory = $false,
            Position = 2,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ActivateWithKMS')]
        [ValidateRange(1, 65535)]
        [int]
        $KMSServerPort = 1688,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Rearm')]
        [switch]
        $Rearm,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ActivateWithKMS')]
        [switch]
        $CacheDisabled,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Offline')]
        [switch]$Offline,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Offline')]
        [ValidateLength(64, 64)]
        [ValidateScript(
            {
                $pattern = [Regex]::new('^[0-9]{64}$')
                if ($pattern.Matches($_).Count -gt 0)
                {
                    $true
                }
                else
                {
                    throw "$_ is invalid. Please provide a valid Confirmation Id"
                }
            })]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfirmationId

    )
    Begin
    {
        $PreviousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        Write-Verbose 'ErrorActionPreference: Stop'
    }
    Process
    {
        if ($pscmdlet.ShouldProcess($Computer -join ', ', 'Activate license via KMS'))
        {
            Write-Verbose "Enumerating computers: $($Computer.Count) computer(s)."
            foreach ($c in $Computer)
            {
                Write-Verbose "Creating new CimSession for computer $c"
                $session = Get-Session -Computer $c -Credentials $Credentials

                Write-Verbose 'Connecting to SoftwareLicensingService..'
                $service = Get-CustomWMIObject -CimSession $session -ClassName SoftwareLicensingService

                try
                {
                    switch ($PSCmdlet.ParameterSetName)
                    {
                        'Offline'
                        {
                            Write-Verbose 'Initiating offline activation operation'
                            Invoke-OfflineActivation -CimSession $session -Service $service -$ConfirmationId
                            exit 0
                        }

                        'Rearm'
                        {
                            Write-Verbose 'Initiating ReArm operation'
                            Invoke-Rearm -CimSession $session -Service $service
                            exit 0
                        }

                        'ActivateWithKMS'
                        {
                            Write-Verbose "Changing KMS cache setting as: $($CacheDisabled.IsPresent -eq $false)"
                            if ($CacheDisabled.IsPresent)
                            {
                                $service.DisableKeyManagementServiceHostCaching(1) > $null # Disable caching
                            }

                            Write-Verbose 'Initiating KMS activation operation'
                            Invoke-KMSActivation $PSBoundParameters -CimSession $session -Service $service
                            exit 0
                        }

                        default
                        {
                            throw 'Unknown parameter combination' # We do not expect this to be triggered at all but it is here to prevent human errors
                        }
                    }
                    if ($null -ne $session)
                    {
                        Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
                    }
                }
                catch
                {
                    if ($null -ne $session)
                    {
                        Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
                    }
                    exit 1
                }
            }
        }
    }
    End
    {
        $ErrorActionPreference = $PreviousPreference
    }
}
