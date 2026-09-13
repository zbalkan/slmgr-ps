BeforeAll {
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Public command contract stability' {
    It 'preserves established public parameter names' {
        $requiredParameters = @{
            'Get-WindowsActivation' = @('Computer', 'Credentials', 'Extended', 'Expiry', 'Offline', 'ActivationId', 'All')
            'Get-WindowsADActivationInstallationId' = @('ProductKey')
            'Get-WindowsADActivationObject' = @('Name', 'DistinguishedName', 'DirectoryServer', 'DirectoryCredential')
            'Get-WindowsKmsHost' = @('Computer', 'Credentials')
            'Get-WindowsTokenActivationLicense' = @('Computer', 'Credentials')
            'Install-WindowsLicense' = @('Computer', 'Credentials', 'Path')
            'New-WindowsADActivationObject' = @('ProductKey', 'ActivationObjectName', 'ConfirmationId', 'DirectoryServer', 'DirectoryCredential')
            'Remove-WindowsADActivationObject' = @('DistinguishedName', 'DirectoryServer', 'DirectoryCredential')
            'Remove-WindowsTokenActivationLicense' = @('Computer', 'Credentials', 'ILID', 'ILVID')
            'Reset-WindowsActivation' = @('Computer', 'Credentials', 'UninstallProductKey', 'ClearProductKeyFromRegistry', 'ClearKMSSettings', 'ClearKMSLookupDomain', 'ActivationId')
            'Set-WindowsActivationType' = @('Computer', 'Credentials', 'ActivationType', 'ActivationId')
            'Set-WindowsKmsClient' = @('Computer', 'Credentials', 'KmsServer', 'Port', 'LookupDomain', 'HostCaching', 'ActivationId')
            'Set-WindowsKmsHost' = @('Computer', 'Credentials', 'ListeningPort', 'ClearListeningPort', 'ActivationInterval', 'RenewalInterval', 'DnsPublishing', 'Priority')
            'Start-WindowsActivation' = @('Computer', 'Credentials', 'KMSServerFQDN', 'KMSServerPort', 'Rearm', 'ApplicationId', 'CacheDisabled', 'UseKmsClientKey', 'ProductKey', 'ActivationId', 'Offline', 'ConfirmationId')
        }

        foreach ($entry in $requiredParameters.GetEnumerator())
        {
            $command = Get-Command $entry.Key -Module slmgr-ps -ErrorAction Stop
            foreach ($parameterName in $entry.Value)
            {
                $command.Parameters.Keys | Should -Contain $parameterName
            }
        }
    }

    It 'preserves KmsServer as an alias for Start-WindowsActivation KMSServerFQDN' {
        $parameter = (Get-Command Start-WindowsActivation -Module slmgr-ps).Parameters['KMSServerFQDN']
        @($parameter.Aliases) | Should -Contain 'KmsServer'
    }

    It 'does not export aliases or cmdlets from the script module' {
        $module = Get-Module slmgr-ps
        $module.ExportedAliases.Count | Should -Be 0
        $module.ExportedCmdlets.Count | Should -Be 0
    }
}
