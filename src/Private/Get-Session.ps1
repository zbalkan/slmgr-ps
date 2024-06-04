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

    if ($Computer.Count -eq 1 -and $Computer[0] -eq 'localhost' -or $Computer[0] -eq '.' -or $Computer[0] -eq '127.0.0.1' -or $null -eq $Computer[0])
    {
        Write-Verbose 'Using DCOM protocol for CIM session'
        if ($null -eq $Credentials)
        {
            $session = New-CimSession -Name 'SlmgrLocalSession'
        }
        else
        {
            $session = New-CimSession -Name 'SlmgrLocalSession' -Credential $Credentials
        }
    }
    else # if multiple hosts are given including localhost, then it will try to use WinRM, instead of DCOM.
    {
        Write-Verbose 'Using WinRM protocol for CIM session'
        $session = New-CimSession $PSBoundParameters -Name 'SlmgrRemoteSession'
    }
    return $session
}
