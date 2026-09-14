#Requires -Version 5

function Get-WindowsKmsHost
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
                $service = Get-KmsHostService -CimSession $session -ErrorAction Stop

                $configuredPort = [uint32]$service.KeyManagementServiceListeningPort
                $activationDisabled = $null
                if ($null -ne $service.PSObject.Properties['KeyManagementServiceActivationDisabled'])
                {
                    $activationDisabled = [bool]$service.KeyManagementServiceActivationDisabled
                }

                $result = [PSCustomObject][ordered]@{
                    ComputerName                    = $c
                    IsKmsHost                       = $true
                    ListeningPortConfigured         = ($configuredPort -ne 0)
                    ConfiguredListeningPort         = if ($configuredPort -eq 0) { $null } else { $configuredPort }
                    EffectiveListeningPort          = if ($configuredPort -eq 0) { [uint32]1688 } else { $configuredPort }
                    ActivationInterval              = [uint32]$service.VLActivationInterval
                    RenewalInterval                 = [uint32]$service.VLRenewalInterval
                    DnsPublishing                   = if ($service.KeyManagementServiceDnsPublishing) { 'Enabled' } else { 'Disabled' }
                    Priority                        = if ($service.KeyManagementServiceLowPriority) { 'Low' } else { 'Normal' }
                    CurrentClientCount              = [uint32]$service.KeyManagementServiceCurrentCount
                    RequiredClientCount             = [uint32]$service.RequiredClientCount
                    ProductKeyId                    = $service.KeyManagementServiceProductKeyID
                    ActivationDisabled              = $activationDisabled
                    UnlicensedRequests              = [uint32]$service.KeyManagementServiceUnlicensedRequests
                    LicensedRequests                = [uint32]$service.KeyManagementServiceLicensedRequests
                    OobGraceRequests                = [uint32]$service.KeyManagementServiceOOBGraceRequests
                    OotGraceRequests                = [uint32]$service.KeyManagementServiceOOTGraceRequests
                    NonGenuineGraceRequests         = [uint32]$service.KeyManagementServiceNonGenuineGraceRequests
                    NotificationRequests            = [uint32]$service.KeyManagementServiceNotificationRequests
                    TotalRequests                   = [uint32]$service.KeyManagementServiceTotalRequests
                    FailedRequests                  = [uint32]$service.KeyManagementServiceFailedRequests
                    DefaultListeningPort            = [uint32]1688
                    DefaultActivationInterval       = [uint32]120
                    DefaultRenewalInterval          = [uint32]10080
                }
                $result.PSObject.TypeNames.Insert(0, 'slmgr-ps.KmsHostStatus')
                Write-Output $result
            }
            catch
            {
                $PSCmdlet.WriteError($_)
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
