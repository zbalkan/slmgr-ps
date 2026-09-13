#Requires -Version 5

function Set-WindowsKmsHost
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', PositionalBinding = $false)]
    param(
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [AllowNull()]
        [string[]]$Computer = @('localhost'),

        [Parameter()]
        [AllowNull()]
        [PSCredential]$Credentials,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [uint32]$ListeningPort,

        [Parameter()]
        [switch]$ClearListeningPort,

        [Parameter()]
        [ValidateRange(15, 43200)]
        [uint32]$ActivationInterval,

        [Parameter()]
        [ValidateRange(15, 43200)]
        [uint32]$RenewalInterval,

        [Parameter()]
        [ValidateSet('Enabled', 'Disabled')]
        [string]$DnsPublishing,

        [Parameter()]
        [ValidateSet('Normal', 'Low')]
        [string]$Priority
    )

    begin
    {
        if ($PSBoundParameters.ContainsKey('ListeningPort') -and $ClearListeningPort.IsPresent)
        {
            throw 'ListeningPort and ClearListeningPort cannot be used together.'
        }

        $hasSetting = $PSBoundParameters.ContainsKey('ListeningPort') -or
            $ClearListeningPort.IsPresent -or
            $PSBoundParameters.ContainsKey('ActivationInterval') -or
            $PSBoundParameters.ContainsKey('RenewalInterval') -or
            $PSBoundParameters.ContainsKey('DnsPublishing') -or
            $PSBoundParameters.ContainsKey('Priority')
        if (-not $hasSetting)
        {
            throw 'Specify at least one KMS host setting.'
        }

        $failures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
    }

    process
    {
        foreach ($c in $Computer)
        {
            $settings = [System.Collections.Generic.List[object]]::new()
            if ($PSBoundParameters.ContainsKey('ListeningPort'))
            {
                $settings.Add([PSCustomObject]@{
                        Operation = 'SetKmsHostListeningPort'
                        Action = "Set KMS host listening port to $ListeningPort"
                        Method = 'SetKeyManagementServiceListeningPort'
                        Arguments = @{ PortNumber = $ListeningPort }
                        Property = 'KeyManagementServiceListeningPort'
                        Expected = [uint32]$ListeningPort
                    })
            }
            elseif ($ClearListeningPort.IsPresent)
            {
                $settings.Add([PSCustomObject]@{
                        Operation = 'ClearKmsHostListeningPort'
                        Action = 'Clear KMS host listening-port override'
                        Method = 'ClearKeyManagementServiceListeningPort'
                        Arguments = $null
                        Property = 'KeyManagementServiceListeningPort'
                        Expected = [uint32]0
                    })
            }
            if ($PSBoundParameters.ContainsKey('ActivationInterval'))
            {
                $settings.Add([PSCustomObject]@{
                        Operation = 'SetKmsHostActivationInterval'
                        Action = "Set KMS host activation interval to $ActivationInterval minutes"
                        Method = 'SetVLActivationInterval'
                        Arguments = @{ ActivationInterval = $ActivationInterval }
                        Property = 'VLActivationInterval'
                        Expected = [uint32]$ActivationInterval
                    })
            }
            if ($PSBoundParameters.ContainsKey('RenewalInterval'))
            {
                $settings.Add([PSCustomObject]@{
                        Operation = 'SetKmsHostRenewalInterval'
                        Action = "Set KMS host renewal interval to $RenewalInterval minutes"
                        Method = 'SetVLRenewalInterval'
                        Arguments = @{ RenewalInterval = $RenewalInterval }
                        Property = 'VLRenewalInterval'
                        Expected = [uint32]$RenewalInterval
                    })
            }
            if ($PSBoundParameters.ContainsKey('DnsPublishing'))
            {
                $disablePublishing = $DnsPublishing -eq 'Disabled'
                $settings.Add([PSCustomObject]@{
                        Operation = 'SetKmsHostDnsPublishing'
                        Action = "Set KMS host DNS publishing to $DnsPublishing"
                        Method = 'DisableKeyManagementServiceDnsPublishing'
                        Arguments = @{ DisablePublishing = $disablePublishing }
                        Property = 'KeyManagementServiceDnsPublishing'
                        Expected = (-not $disablePublishing)
                    })
            }
            if ($PSBoundParameters.ContainsKey('Priority'))
            {
                $lowPriority = $Priority -eq 'Low'
                $settings.Add([PSCustomObject]@{
                        Operation = 'SetKmsHostPriority'
                        Action = "Set KMS host priority to $Priority"
                        Method = 'EnableKeyManagementServiceLowPriority'
                        Arguments = @{ EnableLowPriority = $lowPriority }
                        Property = 'KeyManagementServiceLowPriority'
                        Expected = $lowPriority
                    })
            }

            $approved = [System.Collections.Generic.List[object]]::new()
            foreach ($setting in $settings)
            {
                if ($PSCmdlet.ShouldProcess($c, $setting.Action))
                {
                    $approved.Add($setting)
                }
            }
            if ($approved.Count -eq 0)
            {
                continue
            }

            $session = $null
            try
            {
                $session = Get-Session -Computer $c -Credentials $Credentials -ErrorAction Stop
                $service = Get-KmsHostService -CimSession $session -ErrorAction Stop

                foreach ($setting in $approved)
                {
                    try
                    {
                        if ($null -eq $setting.Arguments)
                        {
                            $service | Invoke-SppCimMethod -MethodName $setting.Method
                        }
                        else
                        {
                            $service | Invoke-SppCimMethod -MethodName $setting.Method -Arguments $setting.Arguments
                        }

                        $service = Get-KmsHostService -CimSession $session -ErrorAction Stop
                        $actual = $service.($setting.Property)
                        if ($actual -ne $setting.Expected)
                        {
                            throw "$($setting.Operation) was accepted by the provider but the expected state could not be verified."
                        }

                        New-LicensingOperationResult `
                            -ComputerName $c `
                            -Operation $setting.Operation `
                            -Success $true `
                            -VerificationState Verified
                    }
                    catch
                    {
                        $structured = New-LicensingOperationError `
                            -ErrorRecord $_ `
                            -ComputerName $c `
                            -Operation $setting.Operation
                        $failures.Add($structured.ErrorRecord)
                        Write-Output $structured.Result
                    }
                }
            }
            catch
            {
                $structured = New-LicensingOperationError `
                    -ErrorRecord $_ `
                    -ComputerName $c `
                    -Operation 'ConfigureKmsHost'
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
