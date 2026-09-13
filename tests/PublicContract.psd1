@{
    ContractVersion = '1.x'

    Functions = @{
        'Get-WindowsActivation' = @{
            Parameters = @('Computer', 'Credentials', 'Extended', 'Expiry', 'Offline', 'ActivationId', 'All')
        }
        'Get-WindowsADActivationInstallationId' = @{
            Parameters = @('ProductKey')
        }
        'Get-WindowsADActivationObject' = @{
            Parameters = @('Name', 'DistinguishedName', 'DirectoryServer', 'DirectoryCredential')
        }
        'Get-WindowsKmsHost' = @{
            Parameters = @('Computer', 'Credentials')
        }
        'Get-WindowsTokenActivationLicense' = @{
            Parameters = @('Computer', 'Credentials')
        }
        'Install-WindowsLicense' = @{
            Parameters = @('Computer', 'Credentials', 'Path')
            SupportsShouldProcess = $true
        }
        'New-WindowsADActivationObject' = @{
            Parameters = @('ProductKey', 'ActivationObjectName', 'ConfirmationId', 'DirectoryServer', 'DirectoryCredential')
            SupportsShouldProcess = $true
        }
        'Remove-WindowsADActivationObject' = @{
            Parameters = @('DistinguishedName', 'DirectoryServer', 'DirectoryCredential')
            SupportsShouldProcess = $true
        }
        'Remove-WindowsTokenActivationLicense' = @{
            Parameters = @('Computer', 'Credentials', 'ILID', 'ILVID')
            SupportsShouldProcess = $true
        }
        'Repair-WindowsLicense' = @{
            Parameters = @()
            SupportsShouldProcess = $true
        }
        'Reset-WindowsActivation' = @{
            Parameters = @('Computer', 'Credentials', 'UninstallProductKey', 'ClearProductKeyFromRegistry', 'ClearKMSSettings', 'ClearKMSLookupDomain', 'ActivationId')
            SupportsShouldProcess = $true
        }
        'Set-WindowsActivationType' = @{
            Parameters = @('Computer', 'Credentials', 'ActivationType', 'ActivationId')
            SupportsShouldProcess = $true
        }
        'Set-WindowsKmsClient' = @{
            Parameters = @('Computer', 'Credentials', 'KmsServer', 'Port', 'LookupDomain', 'HostCaching', 'ActivationId')
            ParameterAliases = @{
                KmsServer = @('KMSServerFQDN')
            }
            SupportsShouldProcess = $true
        }
        'Set-WindowsKmsHost' = @{
            Parameters = @('Computer', 'Credentials', 'ListeningPort', 'ClearListeningPort', 'ActivationInterval', 'RenewalInterval', 'DnsPublishing', 'Priority')
            SupportsShouldProcess = $true
        }
        'Start-WindowsActivation' = @{
            Parameters = @('Computer', 'Credentials', 'KMSServerFQDN', 'KMSServerPort', 'Rearm', 'ApplicationId', 'CacheDisabled', 'UseKmsClientKey', 'ProductKey', 'ActivationId', 'Offline', 'ConfirmationId')
            ParameterAliases = @{
                KMSServerFQDN = @('KmsServer')
            }
            SupportsShouldProcess = $true
        }
    }

    ResultContracts = @{
        LicensingOperationResult = @{
            TypeName = 'slmgr-ps.LicensingOperationResult'
            Properties = @(
                'ComputerName'
                'Success'
                'Operation'
                'ActivationId'
                'ProductName'
                'RestartRequired'
                'ErrorCode'
                'ErrorMessage'
                'VerificationState'
            )
            VerificationStates = @(
                'Verified'
                'ProviderAccepted'
                'NotVerifiable'
                'Failed'
            )
        }
    }

    ExportedAliases = @()
    ExportedCmdlets = @()
}
