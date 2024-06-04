# The WMI commands are not supported on PowerShell 6+ as they are deprecated -allegedly.
# They would work with PS5 though. To be safe, we used Get-CimInstance instead of
# Get- WMIObject. Unfortunately, not all properties and methods are available on the CIM
# instances. Therefore, we convert the CIM instances to WMI objects to be able to access those methods.
# Reference: https://rohnspowershellblog.wordpress.com/2013/06/15/converting-a-ciminstance-to-a-managementobject-and-back/
function Get-CustomWMIObject
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'ClassName')]
        [string]$ClassName,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'Query')]
        [string]$Query,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            ParameterSetName = 'InputObject')]
        [ValidateNotNull]
        [ciminstance]$InputObject
    )

    Process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Query')
        {
            $Instance = Get-CimInstance -CimSession $CimSession -Query $Query
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'ClassName')
        {
            $Instance = Get-CimInstance -CimSession $CimSession -ClassName $ClassName
        }
        else
        {
            $Instance = $InputObject
        }

        $Keys = $Instance.CimClass.CimClassProperties |
        Where-Object { $_.Qualifiers.Name -contains 'Key' } |
        Select-Object Name, CimType |
        Sort-Object Name

        $KeyValuePairs = $Keys | ForEach-Object {

            $KeyName = $_.Name
            switch -regex ($_.CimType)
            {
                'Boolean|.Int\d+'
                {
                    # No quotes surrounding value:
                    $Value = $Instance.$KeyName
                }

                'Reference'
                {
                    throw "CimInstance contains a key with type 'Reference'. This isn't currenlty supported (but can be added later)"
                }

                default
                {
                    # Treat it like a string and cross your fingers:
                    $Value = '"{0}"' -f ($Instance.$KeyName -replace "`"", "\`"")
                }
            }
            '{0}={1}' -f $KeyName, $Value
        }

        if ($KeyValuePairs)
        {
            $KeyValuePairsString = '.{0}' -f ($KeyValuePairs -join ',')
        }
        else
        {
            # This is how WMI seems to handle paths with no keys
            $KeyValuePairsString = '=@'
        }

        return [wmi]('\\{0}\{1}:{2}{3}' -f $Instance.CimSystemProperties.ServerName,
                               ($Instance.CimSystemProperties.Namespace -replace '/', '\'),
            $Instance.CimSystemProperties.ClassName,
            $KeyValuePairsString)
    }
}
