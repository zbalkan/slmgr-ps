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
            'PartialProductKey'
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
            ClearKeyManagementServicePort = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @()
            }
            ClearProductKeyFromRegistry = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @()
            }
            DepositOfflineConfirmationId = @{
                Classes   = @('SoftwareLicensingProduct')
                Arguments = @('InstallationId', 'ConfirmationId')
            }
            DisableKeyManagementServiceHostCaching = @{
                Classes   = @('SoftwareLicensingService')
                Arguments = @()
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
            SetKeyManagementServicePort = @{
                Classes   = @('SoftwareLicensingService', 'SoftwareLicensingProduct')
                Arguments = @('PortNumber')
            }
            UninstallProductKey = @{
                Classes   = @('SoftwareLicensingProduct')
                Arguments = @()
            }
        }
    }
}
