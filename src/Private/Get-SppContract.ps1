function Get-SppContract
{
    [CmdletBinding()]
    param()

    return @{
        ProductProperties = @(
            'ApplicationID',
            'ID',
            'LicenseIsAddon',
            'LicenseStatus',
            'OfflineInstallationId',
            'PartialProductKey',
            'KeyManagementServiceMachine',
            'KeyManagementServicePort',
            'DiscoveredKeyManagementServiceMachineName',
            'DiscoveredKeyManagementServiceMachinePort',
            'KeyManagementServiceLookupDomain',
            'VLActivationType',
            'VLActivationTypeEnabled'
        )
        ServiceProperties = @(
            'KeyManagementServiceHostCaching'
        )
        Methods = @{
            Activate = @{
                Classes   = @('SoftwareLicensingProduct')
                Arguments = @()
            }
            ClearKeyManagementServiceMachine = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @()
            }
            ClearKeyManagementServiceLookupDomain = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @()
            }
            ClearKeyManagementServicePort = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @()
            }
            ClearProductKeyFromRegistry = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @()
            }
            ClearVLActivationTypeEnabled = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @()
            }
            DepositOfflineConfirmationId = @{
                Classes   = @('SoftwareLicensingProduct')
                Arguments = @('InstallationId', 'ConfirmationId')
            }
            DisableKeyManagementServiceHostCaching = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('DisableCaching')
            }
            InstallProductKey = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('ProductKey')
            }
            InstallLicense = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('License')
            }
            ReArmApp = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('ApplicationId')
            }
            ReArmSku = @{
                Classes   = @('SoftwareLicensingProduct')
                Arguments = @()
            }
            ReArmWindows = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @()
            }
            RefreshLicenseStatus = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @()
            }
            SetKeyManagementServiceMachine = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @('MachineName')
            }
            SetKeyManagementServiceLookupDomain = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @('LookupDomain')
            }
            SetKeyManagementServicePort = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @('PortNumber')
            }
            SetVLActivationTypeEnabled = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @('ActivationType')
            }
            UninstallProductKey = @{
                Classes   = @('SoftwareLicensingProduct')
                Arguments = @()
            }
        }
    }
}
