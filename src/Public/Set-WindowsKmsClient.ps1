#Requires -Version 5

<#
.SYNOPSIS
Configures Windows KMS client discovery and caching.
.DESCRIPTION
Configures a KMS server endpoint, a DNS lookup domain, or service-wide KMS host
caching. Endpoint and lookup-domain settings can target an exact licensing product
with ActivationId. Host caching is a SoftwareLicensingService setting.
.INPUTS
String[]. You can pass computer names.
.OUTPUTS
slmgr-ps.LicensingOperationResult. One result is emitted for each attempted computer.
Throws one aggregate error after processing the requested computer batch when any
computer fails.
.EXAMPLE
Set-WindowsKmsClient -KmsServer kms01.example.test
.EXAMPLE
Set-WindowsKmsClient -KmsServer '[2001:db8::10]:1689'
.EXAMPLE
Set-WindowsKmsClient -Port 2500
.EXAMPLE
Set-WindowsKmsClient -LookupDomain activation.example.test
.EXAMPLE
Set-WindowsKmsClient -HostCaching Disabled
.EXAMPLE
Set-WindowsKmsClient -KmsServer kms01 -Port 2500 -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Set-WindowsKmsClient
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'PortOnly')]
    param(
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Endpoint')]
        [Parameter(ParameterSetName = 'PortOnly')]
        [Parameter(ParameterSetName = 'LookupDomain')]
        [Parameter(ParameterSetName = 'HostCaching')]
        [AllowNull()]
        [string[]]$Computer = @('localhost'),

        [Parameter(ParameterSetName = 'Endpoint')]
        [Parameter(ParameterSetName = 'PortOnly')]
        [Parameter(ParameterSetName = 'LookupDomain')]
        [Parameter(ParameterSetName = 'HostCaching')]
        [AllowNull()]
        [PSCredential]$Credentials,

        [Parameter(Mandatory, ParameterSetName = 'Endpoint')]
        [Alias('KMSServerFQDN')]
        [ValidateNotNullOrEmpty()]
        [string]$KmsServer,

        [Parameter(ParameterSetName = 'Endpoint')]
        [Parameter(Mandatory, ParameterSetName = 'PortOnly')]
        [ValidateRange(1, 65535)]
        [int]$Port = 1688,

        [Parameter(Mandatory, ParameterSetName = 'LookupDomain')]
        [ValidateNotNullOrEmpty()]
        [string]$LookupDomain,

        [Parameter(Mandatory, ParameterSetName = 'HostCaching')]
        [ValidateSet('Enabled', 'Disabled')]
        [string]$HostCaching,

        [Parameter(ParameterSetName = 'Endpoint')]
        [Parameter(ParameterSetName = 'PortOnly')]
        [Parameter(ParameterSetName = 'LookupDomain')]
        [Guid]$ActivationId
    )

    begin
    {
        $hasActivationId = $PSBoundParameters.ContainsKey('ActivationId')
        $resultActivationId = if ($hasActivationId) { $ActivationId } else { $null }
        $configurationFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()

        if ($PSCmdlet.ParameterSetName -eq 'Endpoint')
        {
            $endpointParameters = @{ Endpoint = $KmsServer }
            if ($PSBoundParameters.ContainsKey('Port')) { $endpointParameters['Port'] = $Port }
            $resolvedEndpoint = Resolve-KmsEndpoint @endpointParameters
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'LookupDomain')
        {
            $resolvedLookupDomain = Resolve-KmsLookupDomain -LookupDomain $LookupDomain
        }

        $operation = switch ($PSCmdlet.ParameterSetName)
        {
            'Endpoint' { 'SetKmsEndpoint' }
            'PortOnly' { 'SetKmsPort' }
            'LookupDomain' { 'SetKmsLookupDomain' }
            'HostCaching' { 'SetKmsHostCaching' }
        }
    }

    process
    {
        foreach ($c in $Computer)
        {
            $action = switch ($PSCmdlet.ParameterSetName)
            {
                'Endpoint' { "Set KMS server to $($resolvedEndpoint.Host):$($resolvedEndpoint.Port)" }
                'PortOnly' { "Set KMS server port to $Port" }
                'LookupDomain' { "Set KMS lookup domain to $resolvedLookupDomain" }
                'HostCaching' { "Set KMS host caching to $HostCaching" }
            }
            if (-not $PSCmdlet.ShouldProcess($c, $action)) { continue }

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

                switch ($PSCmdlet.ParameterSetName)
                {
                    'Endpoint'
                    {
                        $target | Invoke-SppCimMethod -MethodName SetKeyManagementServiceMachine `
                            -Arguments @{ MachineName = $resolvedEndpoint.Host }
                        $target | Invoke-SppCimMethod -MethodName SetKeyManagementServicePort `
                            -Arguments @{ PortNumber = $resolvedEndpoint.Port }
                    }
                    'PortOnly'
                    {
                        $target | Invoke-SppCimMethod -MethodName SetKeyManagementServicePort `
                            -Arguments @{ PortNumber = $Port }
                    }
                    'LookupDomain'
                    {
                        $target | Invoke-SppCimMethod -MethodName SetKeyManagementServiceLookupDomain `
                            -Arguments @{ LookupDomain = $resolvedLookupDomain }
                    }
                    'HostCaching'
                    {
                        $disableCaching = $HostCaching -eq 'Disabled'
                        $target | Invoke-SppCimMethod `
                            -MethodName DisableKeyManagementServiceHostCaching `
                            -Arguments @{ DisableCaching = $disableCaching }
                    }
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
                $configurationFailures.Add($structured.ErrorRecord)
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
        Complete-LicensingOperationBatch -Failures $configurationFailures
    }
}
