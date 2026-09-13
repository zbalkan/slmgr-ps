#Requires -Version 5

<#
.Synopsis
Installs product keys or activates Windows
.DESCRIPTION
A drop in replacement for slmgr script. By default attempts activation using the product
key already installed on the machine. Use -UseKmsClientKey to also install the
KMS client setup key (GVLK) for the detected OS edition before activating. This is a
material licensing change and is therefore opt-in. Use -ProductKey to install an
explicit product key before activating it in the same operation.
.INPUTS
string[]. You can pass the computer names
.OUTPUTS
slmgr-ps.LicensingOperationResult. One result is emitted for each attempted computer.
Throws one aggregate error after processing the requested computer batch when any
computer fails.
.EXAMPLE
Start-WindowsActivation -Verbose
.EXAMPLE
Start-WindowsActivation -UseKmsClientKey -Verbose
.EXAMPLE
Start-WindowsActivation -ProductKey XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
.EXAMPLE
Start-WindowsActivation -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
.EXAMPLE
Start-WindowsActivation -Computer WS01 -Credentials (Get-Credential)
.EXAMPLE
Start-WindowsActivation -Computer WS01, WS02 -CacheDisabled
.EXAMPLE
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500
.EXAMPLE
Start-WindowsActivation -ReArm
.EXAMPLE
Start-WindowsActivation -ReArm -ApplicationId 11111111-2222-3333-4444-555555555555
.EXAMPLE
Start-WindowsActivation -ReArm -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
.EXAMPLE
Start-WindowsActivation -Offline -ConfirmationID 123456-123456-123456-123456-123456-123456-123456-123456-123456
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Start-WindowsActivation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'ActivateWithKMS')]
    Param
    (
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
        [Alias('KmsServer')]
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
            ParameterSetName = 'Rearm')]
        [Guid]
        $ApplicationId,

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
            ParameterSetName = 'ActivateWithKMS')]
        [switch]
        $UseKmsClientKey,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ActivateWithKMS')]
        [string]
        $ProductKey,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ActivateWithKMS')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Rearm')]
        [Guid]
        $ActivationId,

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
        $hasProductKey = $PSBoundParameters.ContainsKey('ProductKey')
        $hasActivationId = $PSBoundParameters.ContainsKey('ActivationId')
        $hasApplicationId = $PSBoundParameters.ContainsKey('ApplicationId')
        if ($PSCmdlet.ParameterSetName -eq 'Rearm' -and -not $Rearm.IsPresent)
        {
            throw 'ApplicationId and ActivationId require the Rearm switch in the rearm parameter set.'
        }
        if ($hasApplicationId -and $hasActivationId)
        {
            throw 'ApplicationId and ActivationId cannot be used together for rearm.'
        }
        if ($UseKmsClientKey.IsPresent -and $hasProductKey)
        {
            throw 'UseKmsClientKey and ProductKey cannot be used together.'
        }
        if ($hasActivationId -and ($UseKmsClientKey.IsPresent -or $hasProductKey))
        {
            throw 'ActivationId cannot be combined with product-key installation because InstallProductKey is service-scoped.'
        }
        $hasInvalidProductKey = $ProductKey -notmatch '^[A-Za-z0-9]{5}(?:-[A-Za-z0-9]{5}){4}$'
        if ($hasProductKey -and $hasInvalidProductKey)
        {
            throw 'ProductKey must contain five groups of five alphanumeric characters separated by dashes.'
        }
        if ($PSBoundParameters.ContainsKey('KMSServerFQDN'))
        {
            $endpointParameters = @{ Endpoint = $KMSServerFQDN }
            if ($PSBoundParameters.ContainsKey('KMSServerPort'))
            {
                $endpointParameters['Port'] = $KMSServerPort
            }
            $resolvedKmsEndpoint = Resolve-KmsEndpoint @endpointParameters
        }

        $activationFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $requestedActivationId = if ($hasActivationId) { $ActivationId } else { $null }
        $operation = switch ($PSCmdlet.ParameterSetName)
        {
            'Offline' { 'OfflineActivation' }
            'Rearm'
            {
                if ($hasApplicationId) { 'RearmApplication' }
                elseif ($hasActivationId) { 'RearmSku' }
                else { 'RearmWindows' }
            }
            default { 'Activate' }
        }
    }
    Process
    {
        Write-Verbose "Enumerating computers: $($Computer.Count) computer(s)."
        foreach ($c in $Computer)
        {
            $action = switch ($PSCmdlet.ParameterSetName)
            {
                'Offline' { 'Apply an offline Windows confirmation ID' }
                'Rearm'
                {
                    if ($hasApplicationId) { "Rearm application $ApplicationId" }
                    elseif ($hasActivationId) { "Rearm licensing product $ActivationId" }
                    else { 'Rearm Windows' }
                }
                default { 'Activate Windows' }
            }
            if (-not $pscmdlet.ShouldProcess($c, $action))
            {
                continue
            }

            Write-Verbose "Creating new CimSession for computer $c"
            $session = $null
            $outcome = $null
            try
            {
                $session = Get-Session -Computer $c -Credentials $Credentials -ErrorAction Stop

                Write-Verbose 'Connecting to SoftwareLicensingService...'
                $service = Get-CimInstance -CimSession $session -ClassName SoftwareLicensingService -ErrorAction Stop

                switch ($PSCmdlet.ParameterSetName)
                {
                    'Offline'
                    {
                        Write-Verbose 'Initiating offline activation operation'
                        $offlineParams = @{
                            CimSession     = $session
                            Service        = $service
                            ConfirmationId = $ConfirmationId
                        }
                        if ($hasActivationId) { $offlineParams['ActivationId'] = $ActivationId }
                        $outcome = Invoke-OfflineActivation @offlineParams
                    }

                    'Rearm'
                    {
                        Write-Verbose 'Initiating ReArm operation'
                        $rearmParams = @{ CimSession = $session; Service = $service }
                        if ($hasApplicationId) { $rearmParams['ApplicationId'] = $ApplicationId }
                        if ($hasActivationId) { $rearmParams['ActivationId'] = $ActivationId }
                        $outcome = Invoke-Rearm @rearmParams
                    }

                    'ActivateWithKMS'
                    {
                        if ($CacheDisabled.IsPresent)
                        {
                            Write-Verbose 'Disabling KMS host caching'
                            $service | Invoke-SppCimMethod `
                                -MethodName DisableKeyManagementServiceHostCaching `
                                -Arguments @{ DisableCaching = $true }
                        }

                        Write-Verbose 'Initiating Windows activation operation'
                        $kmsParams = @{ CimSession = $session; Service = $service }
                        if ($PSBoundParameters.ContainsKey('KMSServerFQDN'))
                        {
                            $kmsParams['KMSServerFQDN'] = $resolvedKmsEndpoint.Host
                            $kmsParams['KMSServerPort'] = $resolvedKmsEndpoint.Port
                        }
                        elseif ($PSBoundParameters.ContainsKey('KMSServerPort'))
                        {
                            $kmsParams['KMSServerPort'] = $KMSServerPort
                        }
                        if ($UseKmsClientKey.IsPresent) { $kmsParams['InstallKmsClientKey'] = $true }
                        if ($hasProductKey) { $kmsParams['ProductKey'] = $ProductKey }
                        if ($hasActivationId) { $kmsParams['ActivationId'] = $ActivationId }
                        $outcome = Invoke-KMSActivation @kmsParams
                    }

                    default
                    {
                        throw 'Unknown parameter combination'
                    }
                }

                $resultActivationId = if ($null -ne $outcome -and $null -ne $outcome.ActivationId)
                {
                    $outcome.ActivationId
                }
                else
                {
                    $requestedActivationId
                }
                $productName = if ($null -ne $outcome) { $outcome.ProductName } else { $null }
                $verificationState = if ($null -ne $outcome -and -not [string]::IsNullOrEmpty($outcome.VerificationState))
                {
                    $outcome.VerificationState
                }
                else
                {
                    'ProviderAccepted'
                }
                $restartRequired = $false
                if ($null -ne $outcome) { $restartRequired = [bool]$outcome.RestartRequired }
                elseif ($PSCmdlet.ParameterSetName -eq 'Rearm') { $restartRequired = $true }

                New-LicensingOperationResult `
                    -ComputerName $c `
                    -Operation $operation `
                    -Success $true `
                    -ActivationId $resultActivationId `
                    -ProductName $productName `
                    -RestartRequired $restartRequired `
                    -VerificationState $verificationState
            }
            catch
            {
                $structured = New-LicensingOperationError `
                    -ErrorRecord $_ `
                    -ComputerName $c `
                    -Operation $operation `
                    -ActivationId $requestedActivationId `
                    -RestartRequired ($PSCmdlet.ParameterSetName -eq 'Rearm')
                $activationFailures.Add($structured.ErrorRecord)
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
        Complete-LicensingOperationBatch -Failures $activationFailures
    }
}
