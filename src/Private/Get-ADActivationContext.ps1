function Get-ADActivationContext
{
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    if ($null -eq (Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1))
    {
        throw 'The ActiveDirectory PowerShell module is required for Active Directory activation-object operations.'
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $common = @{}
    if ($PSBoundParameters.ContainsKey('Server')) { $common['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $common['Credential'] = $Credential }

    $rootDse = Get-ADRootDSE @common -ErrorAction Stop
    $forest = Get-ADForest @common -ErrorAction Stop
    $domain = Get-ADDomain @common -ErrorAction Stop

    $containers = @(Get-ADObject @common -LDAPFilter '(objectClass=msSPP-ActivationObjectsContainer)' -SearchBase $rootDse.ConfigurationNamingContext -SearchScope Subtree -ErrorAction Stop)
    if ($containers.Count -eq 0)
    {
        throw 'The Active Directory activation-objects container was not found. Verify that the forest schema supports Active Directory-based activation.'
    }
    if ($containers.Count -ne 1)
    {
        throw 'Multiple Active Directory activation-objects containers were returned; the directory state is ambiguous.'
    }

    [PSCustomObject]@{
        Forest                     = $forest.Name
        Domain                     = $domain.DNSRoot
        ConfigurationNamingContext = $rootDse.ConfigurationNamingContext
        ContainerDistinguishedName = $containers[0].DistinguishedName
    }
}
