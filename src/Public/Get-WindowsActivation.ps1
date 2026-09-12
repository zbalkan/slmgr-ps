#Requires -Version 5

<#
.Synopsis
Collects Windows license information
.DESCRIPTION
A drop in replacement for slmgr script /dli and /dlv options
.INPUTS
string[]. You can pass the computer names
.OUTPUTS
psobject. The number of properties depends on basic or extended mode.
.EXAMPLE
Get-WindowsActivation # Collects basic license information of local computer, equal to slmgr.vbs /dli
.EXAMPLE
Get-WindowsActivation -Extended # Collects extended license information of local computer, equal to slmgr.vbs /dlv
.EXAMPLE
Get-WindowsActivation -Expiry # Collects license expiration information of local computer, equal to slmgr.vbs /xpr
.EXAMPLE
Get-WindowsActivation -Computer WS01 # Collects basic license information of computer WS01 over WinRM
.EXAMPLE
Get-WindowsActivation -Computer WS01 -Credentials (Get-Credential) # Collects basic license information of computer WS01 over WinRM using different credentials
.EXAMPLE
Get-WindowsActivation -Offline # Get the offline installation ID for offline -aka phone- activation
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Get-WindowsActivation
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(
        PositionalBinding = $true,
        DefaultParameterSetName = 'Basic')]
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'Extended')]
        [Parameter(ParameterSetName = 'Expiry')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [string[]]
        $Computer = @('localhost'),

        # Define credentials other than current user if needed
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'Extended')]
        [Parameter(ParameterSetName = 'Expiry')]
        [Parameter(ParameterSetName = 'Offline')]
        [AllowNull()]
        [PSCredential]
        $Credentials,

        [Parameter(Mandatory = $false, ParameterSetName = 'Extended')]
        [switch]$Extended,

        [Parameter(Mandatory = $false, ParameterSetName = 'Expiry')]
        [switch]$Expiry,

        [Parameter(ParameterSetName = 'Offline')]
        [switch]$Offline,

        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'Extended')]
        [Parameter(ParameterSetName = 'Expiry')]
        [Parameter(ParameterSetName = 'Offline')]
        [Guid]$ActivationId
    )
    Begin
    {
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    Process
    {
        Write-Verbose "Enumerating computers: $($Computer.Count) computer(s)."
        foreach ($c in $Computer)
        {
            Write-Verbose "Creating new CimSession for computer $c"
            $session = Get-Session -Computer $c -Credentials $Credentials -ErrorAction Stop
            try
            {
                $informationParams = @{ CimSession = $session; ErrorAction = 'Stop' }
                if ($PSBoundParameters.ContainsKey('ActivationId'))
                {
                    $informationParams['Product'] = Get-WindowsLicensingProduct -CimSession $session `
                        -ActivationId $ActivationId -ErrorAction Stop
                }

                switch ($PSCmdlet.ParameterSetName)
                {
                    'Extended'
                    {
                        $result = Get-ExtendedLicenseInformation @informationParams
                    }
                    'Expiry'
                    {
                        $result = Get-ExpiryInformation @informationParams
                    }
                    'Offline'
                    {
                        $result = Get-OfflineInstallationId @informationParams
                    }
                    default
                    {
                        $result = Get-BasicLicenseInformation @informationParams
                    }
                }
                $results.Add($result)
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
        return $results.ToArray()
    }
}
