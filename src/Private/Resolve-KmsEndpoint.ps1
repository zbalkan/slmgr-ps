function Test-KmsDnsName
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [switch]$RequireFqdn
    )

    if ($Name -notmatch '^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$')
    {
        return $false
    }
    if ($RequireFqdn.IsPresent -and $Name.TrimEnd([char]'.') -notmatch '\.')
    {
        return $false
    }
    return $true
}

function Resolve-KmsLookupDomain
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$LookupDomain
    )

    $value = $LookupDomain.Trim()
    $address = $null
    if ($value.Length -eq 0 -or $value -match '\s' -or
        [System.Net.IPAddress]::TryParse($value.Trim([char[]]'[]'), [ref]$address) -or
        -not (Test-KmsDnsName -Name $value -RequireFqdn))
    {
        throw "Invalid KMS lookup domain: $LookupDomain"
    }
    return $value
}

function Resolve-KmsEndpoint
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Endpoint,

        [ValidateRange(1, 65535)]
        [int]$Port = 1688
    )

    $value = $Endpoint.Trim()
    if ($value.Length -eq 0 -or $value -match '\s')
    {
        throw 'KMS server must be a host name, IPv4 address, or bracketed IPv6 address without whitespace.'
    }

    $hostName = $null
    $embeddedPort = $null
    if ($value.StartsWith('['))
    {
        if ($value -notmatch '^\[(?<Host>[^\]]+)\](?::(?<Port>\d+))?$')
        {
            throw "Invalid bracketed KMS server endpoint: $Endpoint"
        }

        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($Matches.Host, [ref]$address) -or
            $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6)
        {
            throw "Invalid IPv6 KMS server address: $($Matches.Host)"
        }
        $hostName = $Matches.Host
        if ($Matches.Port) { $embeddedPort = $Matches.Port }
    }
    else
    {
        $colonCount = ($value.ToCharArray() | Where-Object { $_ -eq ':' }).Count
        if ($colonCount -gt 1)
        {
            throw 'IPv6 KMS server addresses must be enclosed in brackets.'
        }
        if ($colonCount -eq 1)
        {
            $hostName, $embeddedPort = $value.Split(':', 2)
            if ([string]::IsNullOrWhiteSpace($hostName) -or [string]::IsNullOrWhiteSpace($embeddedPort))
            {
                throw "Invalid KMS server endpoint: $Endpoint"
            }
        }
        else
        {
            $hostName = $value
        }

        $address = $null
        $isIpv4Shape = $hostName -match '^\d{1,3}(?:\.\d{1,3}){3}$'
        if ($isIpv4Shape)
        {
            if (-not [System.Net.IPAddress]::TryParse($hostName, [ref]$address) -or
                $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork)
            {
                throw "Invalid IPv4 KMS server address: $hostName"
            }
        }
        elseif ($hostName -match '^[0-9.]+$')
        {
            throw "Invalid IPv4 KMS server address: $hostName"
        }
        elseif (-not (Test-KmsDnsName -Name $hostName))
        {
            throw "Invalid KMS server host name: $hostName"
        }
    }

    if ($null -ne $embeddedPort)
    {
        if ($PSBoundParameters.ContainsKey('Port'))
        {
            throw 'Specify the KMS port either in Endpoint or with Port, not both.'
        }
        $parsedPort = 0
        if (-not [int]::TryParse($embeddedPort, [ref]$parsedPort) -or $parsedPort -lt 1 -or $parsedPort -gt 65535)
        {
            throw "Invalid KMS server port: $embeddedPort"
        }
        $Port = $parsedPort
    }

    [PSCustomObject]@{
        Host = $hostName
        Port = $Port
    }
}
