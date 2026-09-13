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
        [Guid]$ActivationId,

        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'Extended')]
        [switch]$All
    )
    Begin
    {
        if ($All.IsPresent -and $PSBoundParameters.ContainsKey('ActivationId'))
        {
            throw 'ActivationId and All cannot be used together.'
        }

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
                $products = @()
                if ($PSBoundParameters.ContainsKey('ActivationId'))
                {
                    $products = @(Get-WindowsLicensingProduct -CimSession $session `
                            -ActivationId $ActivationId -ErrorAction Stop)
                }
                elseif ($All.IsPresent)
                {
                    $products = @(Get-WindowsLicensingProduct -CimSession $session -All -ErrorAction Stop)
                }
                elseif ($PSCmdlet.ParameterSetName -in @('Basic', 'Extended'))
                {
                    $products = @(Get-WindowsLicensingProduct -CimSession $session -ForRead -ErrorAction Stop)
                }

                $informationFunction = switch ($PSCmdlet.ParameterSetName)
                {
                    'Extended' { 'Get-ExtendedLicenseInformation' }
                    'Expiry' { 'Get-ExpiryInformation' }
                    'Offline' { 'Get-OfflineInstallationId' }
                    default { 'Get-BasicLicenseInformation' }
                }

                $service = $null
                if ($PSCmdlet.ParameterSetName -eq 'Extended')
                {
                    $service = Get-CimInstance -CimSession $session `
                        -ClassName SoftwareLicensingService -ErrorAction Stop
                }

                if ($products.Count -eq 0 -and -not $All.IsPresent)
                {
                    $informationParameters = @{ CimSession = $session; ErrorAction = 'Stop' }
                    if ($null -ne $service) { $informationParameters['Service'] = $service }
                    $result = & $informationFunction @informationParameters
                    $results.Add($result)
                }
                else
                {
                    foreach ($product in $products)
                    {
                        $informationParameters = @{
                            CimSession = $session
                            Product     = $product
                            ErrorAction = 'Stop'
                        }
                        if ($null -ne $service) { $informationParameters['Service'] = $service }
                        $result = & $informationFunction @informationParameters
                        $results.Add($result)
                    }
                }
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
