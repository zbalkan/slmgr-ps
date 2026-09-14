# Comparison with slmgr.vbs

See [README.md](../README.md) for installation, usage examples, and the validation matrix.

The following table compares the current `slmgr-ps` implementation with documented `slmgr.vbs` options.

Microsoft documentation: [Slmgr.vbs options for obtaining volume activation information](https://learn.microsoft.com/en-us/windows-server/get-started/activation-slmgr-vbs-options)

## General command shape

```cmd
slmgr.vbs [<ComputerName> [<User> <Password>]] [<Options>]
```

| `slmgr.vbs` capability   | `slmgr-ps` equivalent           |                Status | Notes                                                                             |
| ------------------------ | ------------------------------- | --------------------: | --------------------------------------------------------------------------------- |
| Local execution          | Default `-Computer localhost`   |             Supported | Local CIM sessions use DCOM.                                                      |
| Remote computer          | `-Computer WS01`                |             Supported | Remote CIM sessions use WinRM, not the old `slmgr.vbs` DCOM/WMI command shape.    |
| Remote user and password | `-Credentials (Get-Credential)` | Supported differently | `slmgr-ps` uses `PSCredential` instead of exposing passwords on the command line. |
| Multiple computers       | `-Computer WS01, WS02`          |             Supported | This is a PowerShell-native improvement over the single-target `slmgr.vbs` style. |

## Global options

| `slmgr.vbs` option     | `slmgr-ps` equivalent                                          |                Status | Notes                                                                                                   |
| ---------------------- | -------------------------------------------------------------- | --------------------: | ------------------------------------------------------------------------------------------------------- |
| `/ipk <ProductKey>`    | `Start-WindowsActivation -ProductKey <ProductKey>`             | Supported differently | Installs the supplied key and immediately attempts activation in the same operation.                    |
| `/ato`                 | `Start-WindowsActivation`                                      |             Supported | Activates the selected Windows licensing product.                                                       |
| `/ato <Activation ID>` | `Start-WindowsActivation -ActivationId <ActivationId>`         |             Supported | Resolves and activates the exact SPP product.                                                           |
| `/dli`                 | `Get-WindowsActivation`                                        |             Supported | Returns basic information for the selected Windows licensing product.                                   |
| `/dli <Activation ID>` | `Get-WindowsActivation -ActivationId <ActivationId>`           |             Supported | Returns basic information for the exact SPP product.                                                    |
| `/dli all`             | `Get-WindowsActivation -All`                                   |             Supported | Returns basic information for every SPP product.                                                        |
| `/dlv`                 | `Get-WindowsActivation -Extended`                              |             Supported | Returns extended information for the selected Windows licensing product.                                |
| `/dlv <Activation ID>` | `Get-WindowsActivation -Extended -ActivationId <ActivationId>` |             Supported | Returns extended information for the exact SPP product.                                                 |
| `/dlv all`             | `Get-WindowsActivation -Extended -All`                         |             Supported | Returns extended information for every SPP product.                                                     |
| `/xpr`                 | `Get-WindowsActivation -Expiry`                                |             Supported | Returns expiry status for the selected Windows licensing product.                                       |
| `/xpr <Activation ID>` | `Get-WindowsActivation -Expiry -ActivationId <ActivationId>`   |             Supported | Returns expiry information for the exact SPP product.                                                   |

## Advanced options

| `slmgr.vbs` option                       | `slmgr-ps` equivalent                                                                            |                Status | Notes                                                                                 |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------: | ------------------------------------------------------------------------------------- |
| `/cpky`                                  | `Reset-WindowsActivation -ClearProductKeyFromRegistry`                                           |             Supported | Clears the product key from registry storage through `SoftwareLicensingService`.      |
| `/ilc <license_file>`                    | `Install-WindowsLicense -Path <license_file>`                                                    | Supported differently | Reads the controller-side `.xrm-ms` file and installs its content through CIM.        |
| `/rilc`                                  | `Repair-WindowsLicense`                                                                          |     Supported locally | Reinstalls `.xrm-ms` files from the local Windows OEM and SPP token directories.      |
| `/rearm`                                 | `Start-WindowsActivation -Rearm`                                                                 |             Supported | Resets activation state where supported by Windows.                                   |
| `/rearm-app <Application ID>`            | `Start-WindowsActivation -Rearm -ApplicationId <ApplicationId>`                                  |             Supported | Rearms the exact application through `SoftwareLicensingService`.                      |
| `/rearm-sku <Activation ID>`             | `Start-WindowsActivation -Rearm -ActivationId <ActivationId>`                                    |             Supported | Resolves and rearms the exact licensing product.                                      |
| `/upk`                                   | `Reset-WindowsActivation -UninstallProductKey`                                                   |             Supported | Uninstalls the product key from the selected Windows licensing product.               |
| `/upk <Activation ID>`                   | `Reset-WindowsActivation -UninstallProductKey -ActivationId <ActivationId>`                      |             Supported | Uninstalls the key from the exact SPP product.                                        |
| `/dti`                                   | `Get-WindowsActivation -Offline`                                                                 |             Supported | Returns the offline installation ID for the selected Windows licensing product.       |
| `/dti <Activation ID>`                   | `Get-WindowsActivation -Offline -ActivationId <ActivationId>`                                    |             Supported | Returns the offline installation ID for the exact SPP product.                        |
| `/atp <Confirmation ID>`                 | `Start-WindowsActivation -Offline -ConfirmationId <Confirmation ID>`                             |             Supported | Applies a confirmation ID to the selected Windows licensing product.                  |
| `/atp <Confirmation ID> <Activation ID>` | `Start-WindowsActivation -Offline -ConfirmationId <ConfirmationId> -ActivationId <ActivationId>` |             Supported | Applies the confirmation ID to the exact SPP product.                                 |

## KMS client options

| `slmgr.vbs` option                    | `slmgr-ps` equivalent                                                    |          Status | Notes                                                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------ | --------------: | ------------------------------------------------------------------------------------------------------------------------- |
| `/skms <Name[:Port]>`                 | `Set-WindowsKmsClient -KmsServer <Name[:Port]>`                          |       Supported | Accepts hostnames, FQDNs, IPv4, and bracketed IPv6. Use `-Port` alone for the `:Port` form.                               |
| `/skms <Name[:Port]> <Activation ID>` | Add `-ActivationId <ActivationId>` to the command above                  |       Supported | Applies the endpoint to the exact licensing product. `Start-WindowsActivation` can configure and activate in one call.    |
| `/skms-domain <FQDN>`                 | `Set-WindowsKmsClient -LookupDomain <FQDN>`                              |       Supported | Configures the service-wide KMS DNS lookup domain.                                                                        |
| `/skms-domain <FQDN> <Activation ID>` | Add `-ActivationId <ActivationId>` to the command above                  |       Supported | Configures the lookup domain on the exact licensing product.                                                              |
| `/ckms`                               | `Reset-WindowsActivation -ClearKMSSettings`                              |       Supported | Clears the configured KMS host name and port while preserving the KMS lookup domain.                                      |
| `/ckms <Activation ID>`               | `Reset-WindowsActivation -ClearKMSSettings -ActivationId <ActivationId>` |       Supported | Clears product-specific KMS client host and port settings.                                                                |
| `/ckms-domain`                        | `Reset-WindowsActivation -ClearKMSLookupDomain`                          |       Supported | Clears the lookup domain without clearing the configured host and port.                                                   |
| `/skhc`                               | `Set-WindowsKmsClient -HostCaching Enabled`                              |       Supported | Enables service-wide KMS host caching.                                                                                    |
| `/ckhc`                               | `Set-WindowsKmsClient -HostCaching Disabled`                             |       Supported | Disables service-wide KMS host caching. `Start-WindowsActivation -CacheDisabled` remains available for combined use.      |

## Volume activation policy

| `slmgr.vbs` option                       | `slmgr-ps` equivalent                                                          |                Status | Notes                                                                 |
| ---------------------------------------- | ------------------------------------------------------------------------------ | --------------------: | --------------------------------------------------------------------- |
| `/act-type`                              | `Set-WindowsActivationType -ActivationType Any`                                | Supported differently | Clears the activation-type restriction.                               |
| `/act-type <0\|1\|2\|3>`                 | `Set-WindowsActivationType -ActivationType <Any\|ActiveDirectory\|Kms\|Token>` | Supported differently | Uses readable PowerShell values instead of numeric policy values.     |
| `/act-type <0\|1\|2\|3> <Activation ID>` | Add `-ActivationId <ActivationId>`                                             | Supported differently | Applies the policy to the exact licensing product.                    |

## KMS server configuration options

| `slmgr.vbs` option | `slmgr-ps` equivalent                                      |                Status | Notes                                                                                          |
| ------------------ | ---------------------------------------------------------- | --------------------: | ---------------------------------------------------------------------------------------------- |
| `/sai <Interval>`  | `Set-WindowsKmsHost -ActivationInterval <Interval>`        |             Supported | Accepts the documented 15–43,200 minute range.                                                 |
| `/sri <Interval>`  | `Set-WindowsKmsHost -RenewalInterval <Interval>`           |             Supported | Accepts the documented 15–43,200 minute range.                                                 |
| `/sprt <Port>`     | `Set-WindowsKmsHost -ListeningPort <Port>`                 |             Supported | Configures the host listening port; the documented default is 1688.                            |
| `/sdns`            | `Set-WindowsKmsHost -DnsPublishing Enabled`                | Supported differently | Uses an explicit readable state instead of opposing switches.                                  |
| `/cdns`            | `Set-WindowsKmsHost -DnsPublishing Disabled`               | Supported differently | Uses an explicit readable state instead of opposing switches.                                  |
| `/spri`            | `Set-WindowsKmsHost -Priority Normal`                      | Supported differently | Uses an explicit readable state instead of opposing switches.                                  |
| `/cpri`            | `Set-WindowsKmsHost -Priority Low`                         | Supported differently | Uses an explicit readable state instead of opposing switches.                                  |

## Token-based activation options

| `slmgr.vbs` option                    | `slmgr-ps` equivalent                                                     |                Status | Notes                                                                        |
| ------------------------------------- | ------------------------------------------------------------------------- | --------------------: | ---------------------------------------------------------------------------- |
| `/lil`                                | `Get-WindowsTokenActivationLicense`                                       |             Supported | Returns installed token activation issuance licenses as structured objects.  |
| `/ril <ILID> <ILvID>`                 | `Remove-WindowsTokenActivationLicense -ILID <ILID> -ILVID <ILVID>`        |             Supported | Requires the exact issuance-license identity and verifies removal.           |
| `/ltc`                                | None                                                                      | Not implemented       | Token activation certificate listing is not currently supported.             |
| `/fta <Certificate Thumbprint>`       | None                                                                      | Not implemented       | Certificate-driven token activation is not currently supported.              |
| `/fta <Certificate Thumbprint> <PIN>` | None                                                                      | Not implemented       | PIN-assisted token activation is not implemented through undocumented paths. |
| `/stao`                               | `Set-WindowsActivationType -ActivationType Token`                         | Supported differently | Uses the modern activation-type policy interface.                            |
| `/ctao`                               | `Set-WindowsActivationType -ActivationType Any`                           | Supported differently | Clears the activation-type restriction.                                      |

## Active Directory-based activation options

| `slmgr.vbs` option                                                                  | `slmgr-ps` equivalent                                                                                                  |                   Status | Notes                                                                                                      |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -----------------------: | ---------------------------------------------------------------------------------------------------------- |
| `/ad-activation-online <Product Key>`                                               | `New-WindowsADActivationObject -ProductKey <ProductKey> -ActivationObjectName <Name>`                                  |    Supported differently | `slmgr-ps` requires an explicit object name so duplicate detection and post-create verification are exact. |
| `/ad-activation-online <Product Key> <Activation Object name>`                      | `New-WindowsADActivationObject -ProductKey <ProductKey> -ActivationObjectName <Name>`                                  |                Supported | Creates and verifies the named activation object.                                                          |
| `/ad-activation-get-iid <Product Key>`                                              | `Get-WindowsADActivationInstallationId -ProductKey <ProductKey>`                                                       |                Supported | Returns structured installation-ID output for a resumable offline workflow.                                |
| `/ad-activation-apply-cid <Product Key> <Confirmation ID>`                          | `New-WindowsADActivationObject -ProductKey <ProductKey> -ConfirmationId <ConfirmationId> -ActivationObjectName <Name>` |    Supported differently | `slmgr-ps` requires an explicit object name.                                                               |
| `/ad-activation-apply-cid <Product Key> <Confirmation ID> <Activation Object name>` | `New-WindowsADActivationObject -ProductKey <ProductKey> -ConfirmationId <ConfirmationId> -ActivationObjectName <Name>` |                Supported | Deposits the confirmation ID and verifies the named object.                                                |
| `/ao-list`                                                                          | `Get-WindowsADActivationObject`                                                                                        |                Supported | Returns structured activation-object records from the AD configuration partition.                          |
| `/del-ao <AO_DN>`                                                                   | `Remove-WindowsADActivationObject -DistinguishedName <AO_DN>`                                                          |                Supported | Requires the exact distinguished name and high-impact confirmation.                                        |
| `/del-ao <AO_RDN>`                                                                  | None                                                                                                                   | Deliberately unsupported | RDN-only deletion is intentionally rejected to avoid ambiguous directory mutations.                        |

## Design differences from slmgr.vbs

`slmgr-ps` is not a direct port of the command-line interface. It uses PowerShell conventions instead.

- It accepts arrays of computer names where the underlying operation supports batching.
- It uses `PSCredential` rather than command-line password arguments.
- It uses CIM sessions for Software Protection Platform remote operations.
- Remote CIM execution uses WinRM.
- KMS client and KMS host configuration are separate commands so client-only settings cannot be confused with host-only methods.
- Active Directory activation-object operations use the ActiveDirectory PowerShell module and directory credentials separately from CIM.
- It returns PowerShell objects for reporting commands and stable operation-result objects for mutating commands.
- It supports PowerShell pipeline-friendly usage.
- It includes KMS client setup keys for supported Windows editions.
- It combines explicit product-key installation and activation in one command.
- It installs license files on multiple targets from controller-side paths.
- It keeps system-license repair local to prevent cross-machine license-file use.
- It requires exact identifiers for destructive token and Active Directory operations rather than accepting ambiguous shorthand.
- It works without Windows Script Host, so environments that block `cscript.exe` and `wscript.exe` can still perform supported activation workflows.
