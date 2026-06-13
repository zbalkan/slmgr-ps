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
Start-WindowsActivation -Computer WS01, WS02 -CacheDisabled # Disables the KMS cache for the computers named WS01 and WS02. Cache is enabled by default.
.EXAMPLE
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500 # Activates the computer named WS01 against server.domain.net:2500
.EXAMPLE
Start-WindowsActivation -ReArm # ReArm the trial period. ReArming already licensed devices can break current license issues. Guard clauses wil protect 99% but cannot guarantee 100%.
.EXAMPLE
Start-WindowsActivation -Offline -ConfirmationID 123456-123456-123456-123456-123456-123456-123456-123456-123456 # Used for offline -aka phone- activation
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
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
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
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
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
        [ValidateScript(
            {
                # Standard Windows phone activation CID: 9 groups of 6 digits separated by dashes
                $pattern = [Regex]::new('^\d{6}(-\d{6}){8}$')
                if ($pattern.Matches($_).Count -gt 0)
                {
                    $true
                }
                else
                {
                    throw "$_ is invalid. Please provide a valid Confirmation Id (9 groups of 6 digits separated by dashes)"
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
                $session = $null
                try
                {
                    $session = Get-Session -Computer $c -Credentials $Credentials

                    Write-Verbose 'Connecting to SoftwareLicensingService...'
                    $service = Get-CimInstance -CimSession $session -ClassName SoftwareLicensingService

                    switch ($PSCmdlet.ParameterSetName)
                    {
                        'Offline'
                        {
                            Write-Verbose 'Initiating offline activation operation'
                            Invoke-OfflineActivation -CimSession $session -Service $service -ConfirmationId $ConfirmationId
                        }

                        'Rearm'
                        {
                            Write-Verbose 'Initiating ReArm operation'
                            Invoke-Rearm -CimSession $session -Service $service
                        }

                        'ActivateWithKMS'
                        {
                            if ($CacheDisabled.IsPresent)
                            {
                                Write-Verbose 'Disabling KMS cache'
                                $service | Invoke-CimMethod -MethodName DisableKeyManagementServiceHostCaching | Out-Null
                            }
                            else
                            {
                                Write-Verbose 'KMS cache: leaving enabled'
                            }

                            Write-Verbose 'Initiating KMS activation operation'
                            $kmsParams = @{ CimSession = $session; Service = $service }
                            if ($PSBoundParameters.ContainsKey('KMSServerFQDN')) { $kmsParams['KMSServerFQDN'] = $KMSServerFQDN }
                            if ($PSBoundParameters.ContainsKey('KMSServerPort')) { $kmsParams['KMSServerPort'] = $KMSServerPort }
                            Invoke-KMSActivation @kmsParams
                        }

                        default
                        {
                            throw 'Unknown parameter combination' # We do not expect this to be triggered at all but it is here to prevent human errors
                        }
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
    }
    End
    {
        $ErrorActionPreference = $PreviousPreference
    }
}
