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
            'VLActivationTypeEnabled',
            'TokenActivationILID',
            'TokenActivationILVID',
            'TokenActivationGrantNumber',
            'TokenActivationCertificateThumbprint',
            'TokenActivationAdditionalInfo',
            'ADActivationObjectName',
            'ADActivationObjectDN',
            'ADActivationCsvlkPid',
            'ADActivationCsvlkSkuId'
        )
        ServiceProperties = @(
            'KeyManagementServiceHostCaching',
            'TokenActivationILID',
            'TokenActivationILVID',
            'TokenActivationGrantNumber',
            'TokenActivationCertificateThumbprint',
            'TokenActivationAdditionalInfo'
        )
        TokenActivationLicenseProperties = @(
            'ID',
            'ILID',
            'ILVID',
            'AuthorizationStatus',
            'ExpirationDate',
            'Description',
            'AdditionalInfo'
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
            DepositActiveDirectoryOfflineActivationConfirmation = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('ProductKey', 'ConfirmationID', 'ActivationObjectName')
            }
            DepositOfflineConfirmationId = @{
                Classes   = @('SoftwareLicensingProduct')
                Arguments = @('InstallationId', 'ConfirmationId')
            }
            DisableKeyManagementServiceHostCaching = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('DisableCaching')
            }
            DoActiveDirectoryOnlineActivation = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('ProductKey', 'ActivationObjectName')
            }
            GenerateActiveDirectoryOfflineActivationId = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('ProductKey')
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
            Uninstall = @{
                Classes   = @('SoftwareLicensingTokenActivationLicense')
                Arguments = @()
            }
            UninstallProductKey = @{
                Classes   = @('SoftwareLicensingProduct')
                Arguments = @()
            }
        }
    }
}
