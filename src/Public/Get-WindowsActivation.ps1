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
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $true,
        ConfirmImpact = 'None',
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
        [switch]$Offline
    )
    Begin
    {
        $PreviousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        Write-Verbose 'ErrorActionPreference: Stop'
    }
    Process
    {
        if ($pscmdlet.ShouldProcess($Computer -join ', ', 'Collect license information'))
        {
            Write-Verbose "Enumerating computers: $($Computer.Count) computer(s)."
            foreach ($c in $Computer)
            {
                Write-Verbose "Creating new CimSession for computer $c"
                $session = Get-Session -Computer $c -Credentials $Credentials

                switch ($PSCmdlet.ParameterSetName)
                {
                    'Extended'
                    {
                        $result = Get-ExtendedLicenseInformation -CimSession $session
                    }
                    'Expiry'
                    {
                        $result = Get-ExpiryInformation -CimSession $session
                    }
                    'Offline'
                    {
                        $result = Get-OfflineInstallationId -CimSession $session
                    }
                    default
                    {
                        $result = Get-BasicLicenseInformation -CimSession $session
                    }
                }
                if ($null -ne $session)
                {
                    Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
                }
                return $result
            }
        }
        End
        {
            $ErrorActionPreference = $PreviousPreference
        }
    }
}
