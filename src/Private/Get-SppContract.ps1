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
            'IsKeyManagementServiceMachine',
            'VLActivationInterval',
            'VLRenewalInterval',
            'KeyManagementServiceCurrentCount',
            'RequiredClientCount',
            'KeyManagementServiceProductKeyID',
            'KeyManagementServiceListeningPort',
            'KeyManagementServiceDnsPublishing',
            'KeyManagementServiceLowPriority',
            'KeyManagementServiceUnlicensedRequests',
            'KeyManagementServiceLicensedRequests',
            'KeyManagementServiceOOBGraceRequests',
            'KeyManagementServiceOOTGraceRequests',
            'KeyManagementServiceNonGenuineGraceRequests',
            'KeyManagementServiceNotificationRequests',
            'KeyManagementServiceTotalRequests',
            'KeyManagementServiceFailedRequests',
            'KeyManagementServiceActivationDisabled',
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
            ClearKeyManagementServiceListeningPort = @{
                Classes   = @('SoftwareLicensingService')
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
            DisableKeyManagementServiceDnsPublishing = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('DisablePublishing')
            }
            DisableKeyManagementServiceHostCaching = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('DisableCaching')
            }
            DoActiveDirectoryOnlineActivation = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('ProductKey', 'ActivationObjectName')
            }
            EnableKeyManagementServiceLowPriority = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('EnableLowPriority')
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
            SetKeyManagementServiceListeningPort = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('PortNumber')
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
            SetVLActivationInterval = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('ActivationInterval')
            }
            SetVLRenewalInterval = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @('RenewalInterval')
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
