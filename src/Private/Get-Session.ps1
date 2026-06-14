function Get-Session
{
    [CmdletBinding()]
    [OutputType([CimSession])]
    param (
        [string[]]
        $Computer,
        [Parameter(Mandatory = $false)]
        [PSCredential]
        $Credentials
    )

    Write-Verbose "Creating sessions for $($Computer.Count) hosts"

    if ($Computer.Count -eq 1 -and ($Computer[0] -eq 'localhost' -or $Computer[0] -eq '.' -or $Computer[0] -eq '127.0.0.1' -or $null -eq $Computer[0]))
    {
        Write-Verbose 'Using DCOM protocol for CIM session'
        $dcomOption = New-CimSessionOption -Protocol Dcom
        if ($null -eq $Credentials)
        {
            $session = New-CimSession -SessionOption $dcomOption -Name 'SlmgrLocalSession'
        }
        else
        {
            $session = New-CimSession -SessionOption $dcomOption -Name 'SlmgrLocalSession' -Credential $Credentials
        }
    }
    else # if multiple hosts are given including localhost, then it will try to use WinRM, instead of DCOM.
    {
        Write-Verbose 'Using WinRM protocol for CIM session'
        $sessionParams = @{ ComputerName = $Computer; Name = 'SlmgrRemoteSession' }
        if ($null -ne $Credentials) { $sessionParams['Credential'] = $Credentials }
        $session = New-CimSession @sessionParams
    }
    return $session
}
