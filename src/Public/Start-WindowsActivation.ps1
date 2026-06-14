#Requires -RunAsAdministrator
#Requires -Version 5

<#
.Synopsis
Activates Windows via KMS
.DESCRIPTION
A drop in replacement for slmgr script. By default attempts KMS activation using the
product key already installed on the machine. Use -UseKmsClientKey to also install the
KMS client setup key (GVLK) for the detected OS edition before activating. This is a
material licensing change and is therefore opt-in.
.INPUTS
string[]. You can pass the computer names
.OUTPUTS
None if successful. Throws on error.
.EXAMPLE
Start-WindowsActivation -Verbose # Activates the local computer using its existing product key
.EXAMPLE
Start-WindowsActivation -UseKmsClientKey -Verbose # Installs the GVLK for the detected OS edition then activates
.EXAMPLE
Start-WindowsActivation -Computer WS01 -Credentials (Get-Credential) # Activates WS01 over WinRM
.EXAMPLE
Start-WindowsActivation -Computer WS01, WS02 -CacheDisabled # Disables the KMS cache on WS01 and WS02
.EXAMPLE
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500 # Activates against a specific KMS server
.EXAMPLE
Start-WindowsActivation -ReArm # ReArm the trial period (guard clauses apply but cannot guarantee 100% safety)
.EXAMPLE
Start-WindowsActivation -Offline -ConfirmationID 123456-123456-123456-123456-123456-123456-123456-123456-123456 # Phone activation
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

        # Installs the KMS client setup key (GVLK) for the detected OS edition before
        # attempting activation. Only needed when the machine currently has a MAK or retail
        # key and must be switched to volume/KMS licensing. This is a material licensing change.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ActivateWithKMS')]
        [switch]
        $UseKmsClientKey,

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
                # Accept 54 digits (9 groups × 6), optionally separated by dashes or spaces
                $stripped = $_ -replace '[\s\-]', ''
                if ($stripped -match '^\d{54}$')
                {
                    $true
                }
                else
                {
                    throw "$_ is not a valid Confirmation ID. Expected 54 digits (9 groups of 6), optionally separated by dashes or spaces."
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
        Write-Verbose "Enumerating computers: $($Computer.Count) computer(s)."
        foreach ($c in $Computer)
        {
            if (-not $pscmdlet.ShouldProcess($c, "Activate Windows ($($PSCmdlet.ParameterSetName))"))
            {
                continue
            }

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
                            Write-Verbose 'Disabling KMS host caching'
                            $service | Invoke-SppCimMethod -MethodName DisableKeyManagementServiceHostCaching
                        }

                        Write-Verbose 'Initiating KMS activation operation'
                        $kmsParams = @{ CimSession = $session; Service = $service }
                        if ($PSBoundParameters.ContainsKey('KMSServerFQDN')) { $kmsParams['KMSServerFQDN'] = $KMSServerFQDN }
                        if ($PSBoundParameters.ContainsKey('KMSServerPort')) { $kmsParams['KMSServerPort'] = $KMSServerPort }
                        if ($UseKmsClientKey.IsPresent) { $kmsParams['InstallKmsClientKey'] = $true }
                        Invoke-KMSActivation @kmsParams
                    }

                    default
                    {
                        throw 'Unknown parameter combination'
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
    End
    {
        $ErrorActionPreference = $PreviousPreference
    }
}
