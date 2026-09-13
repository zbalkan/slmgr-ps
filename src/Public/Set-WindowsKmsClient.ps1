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
None if successful. Throws after processing the requested computer batch when any
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
    }

    process
    {
        $configurationFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
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
            }
            catch
            {
                $configurationFailures.Add($_)
            }
            finally
            {
                if ($null -ne $session)
                {
                    Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
                }
            }
        }

        if ($configurationFailures.Count -gt 0)
        {
            foreach ($failure in $configurationFailures)
            {
                Write-Error -ErrorRecord $failure
            }
            $PSCmdlet.ThrowTerminatingError($configurationFailures[0])
        }
    }
}
