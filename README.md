# slmgr-ps

A partial PowerShell alternative for common `slmgr.vbs` workflows.

`slmgr-ps` is not yet a parameter-compatible or feature-complete replacement for `slmgr.vbs`. The current module focuses on common Windows activation operations, especially licensing status, online and offline activation, license installation and repair, rearm, product-key removal, product-key registry cleanup, and KMS client workflows.

## Changes in 1.5.0

- Added a stable `slmgr-ps.LicensingOperationResult` contract for mutating commands.
- Added explicit `Verified`, `ProviderAccepted`, `NotVerifiable`, and `Failed` verification states.
- Standardized provider failures with hexadecimal SPP/CIM error codes when available and stable operation identifiers.
- Replaced repeated per-target error emission followed by a duplicate first-error throw with one aggregate batch error containing structured failed-target results.
- Expanded extended activation reporting with numeric and readable license status, status reason, evaluation end date, grace and rearm data, service version, client-machine ID, KMS-host state, and activation/renewal intervals.
- Preserved unset provider dates as `$null` rather than artificial minimum dates.

## Changes in 1.4.0

- Added standalone KMS client endpoint, port, lookup-domain, and host-caching configuration.
- Added service-wide and activation-ID-scoped KMS client settings where the SPP provider supports both scopes.
- Added lookup-domain clearing without changing the existing host-and-port-only reset behavior.
- Added hostname, FQDN, IPv4, bracketed IPv6, embedded-port, domain, and port validation before CIM sessions are opened.
- Added configured and discovered KMS client state to extended activation output.
- Corrected KMS host-caching calls to pass the provider's required `DisableCaching` argument.

## Changes in 1.3.0

- Added `.xrm-ms` license-file installation for local and remote computers.
- Added local system-license repair from the Windows OEM and SPP token directories.
- Added application-level and SKU-level rearm with exact GUID targeting.
- Added file, identifier, provider-contract, and pre-session validation for the new operations.
- Added per-file and per-computer failure containment with final terminating errors.
- Added tests for routing, cleanup, `ShouldProcess`, partial failure, and public exports.

## Changes in 1.2.0

- Added explicit product-key installation followed by activation in one command.
- Added activation-ID targeting for license queries, activation, offline activation, key removal, and KMS client settings.
- Added `-All` enumeration for basic and extended license information.
- Added product and application identifiers to license-information output.
- Added batch failure containment for activation and reset operations.
- Added deterministic post-install product selection and final activation-ID verification.
- Added validation that rejects ambiguous product-key and activation-ID combinations.

## Changes in 1.1.2

- Fixed Publish script for master/main branch checks

## Changes in 1.1.1

- Corrected product-key registry clearing to use `SoftwareLicensingService`.
- Corrected KMS reset to clear both the configured host and port while preserving the lookup domain.
- Allowed non-elevated module import for read-only commands.
- Preserved the caller's error-action preference when commands fail.
- Added final-state verification for offline activation.
- Added SPP class-contract, session, and failure-path tests.

## About this module

One of my hardening guidelines is to remove VBScript execution from managed Windows environments where possible.

- I disabled [Windows Script Host](https://www.f-secure.com/en/articles/how-to-disable-windows-script-host), blocking `cscript` and `wscript`.

![Blocked WSH](images/blocked.png "Blocked WSH")

- I changed the file-type association of `.vbs` so `.vbs` files open in Notepad instead of executing.

![.vbs extension is not an executable](images/notepad.png ".vbs extension is not an executable.")

That also meant I could no longer use tools such as `slmgr.vbs`, `OSPP.vbs`, and some SCCM/MDT-related scripts in the same way. I started with `slmgr.vbs` because I needed it during a Windows 7 to Windows 10 migration.

The original version was a small PowerShell script based on `slmgr.vbs`. You can still find the old script in [my gist](https://gist.github.com/zbalkan/4ba92656a3a8387e6b220bcf8fcd5fc6).

This repository turns that script into a PowerShell module so it can be installed and used more easily. You can find it in the [PowerShell Gallery](https://www.powershellgallery.com/packages/slmgr-ps).

Microsoft now provides the official [OSLicense PowerShell module](https://learn.microsoft.com/en-gb/powershell/module/oslicense/?view=windowsserver2025-ps). `slmgr-ps` remains an independent community alternative: it uses the Windows Software Protection Platform CIM interfaces directly and does not import, call, wrap, or depend on OSLicense components.

## Current scope

The module currently exports six public functions:

- `Get-WindowsActivation`
- `Install-WindowsLicense`
- `Repair-WindowsLicense`
- `Set-WindowsKmsClient`
- `Start-WindowsActivation`
- `Reset-WindowsActivation`

The current implementation is intentionally narrower than `slmgr.vbs`. It supports default, activation-ID, and all-product client queries, targeted client activation and reset operations, KMS client configuration, license installation, local system-license repair, and targeted rearm. It does not currently support token-based activation, Active Directory-based activation, or KMS server configuration.

## Operation results and errors

Mutating commands emit a `slmgr-ps.LicensingOperationResult` for each computer on which an operation is attempted. The result contract is stable across activation, rearm, KMS client configuration, reset, license installation, and system-license repair.

| Field | Meaning |
| --- | --- |
| `ComputerName` | Target computer associated with the operation. |
| `Success` | Whether the requested operation completed according to its verification contract. |
| `Operation` | Stable operation identifier suitable for automation. |
| `ActivationId` | Exact affected licensing product identifier when applicable. |
| `ProductName` | Resolved product name when applicable and available. |
| `RestartRequired` | Whether a restart is required before the change is fully effective. |
| `ErrorCode` | SPP or CIM error code formatted as `0xXXXXXXXX` when one is available. Generic PowerShell or .NET errors do not invent a licensing error code. |
| `ErrorMessage` | Provider or exception message without intentionally echoing sensitive command input. |
| `VerificationState` | `Verified`, `ProviderAccepted`, `NotVerifiable`, or `Failed`. |

`Verified` means the module queried a reliable final state and confirmed the intended outcome. `ProviderAccepted` means the documented provider call succeeded but the final state cannot yet be established reliably, such as a rearm operation that requires restart. `NotVerifiable` is reserved for successful operations for which the provider exposes no reliable read-back path. `Failed` identifies a failed target.

For multi-computer operations, the module continues with later targets when it is safe to do so. If any target fails, the command terminates after the batch with a `LicensingBatchFailed` error. Its `TargetObject` contains the failed `LicensingOperationResult` objects, and detailed per-target errors are retained in the exception data. The module does not write the same collected failure repeatedly before throwing the aggregate error.

## Installation

```powershell
Install-Module slmgr-ps
```

## Basic usage

### Get Windows activation information

```powershell
# Basic license information, similar to slmgr.vbs /dli for the selected Windows product
Get-WindowsActivation

# Extended license information, similar to slmgr.vbs /dlv for the selected Windows product
Get-WindowsActivation -Extended

# Expiration information, similar to slmgr.vbs /xpr for the selected Windows product
Get-WindowsActivation -Expiry

# Offline installation ID, similar to slmgr.vbs /dti for offline -aka phone- activation
Get-WindowsActivation -Offline

# Query one product by activation ID
Get-WindowsActivation -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# Enumerate all SPP products in the basic or extended view
Get-WindowsActivation -All
Get-WindowsActivation -Extended -All
```

Extended output includes the raw numeric and readable license status, status reason, grace period, evaluation end date, Windows/application/SKU rearm counts, trusted time, SPP service version, client-machine ID, KMS-host status, volume activation and renewal intervals, configured and discovered KMS host and port values, the KMS lookup domain, and service-wide host-caching state when the provider exposes them. Unset provider dates are returned as `$null`.

### Work with remote computers

```powershell
# Basic license information from a remote computer
Get-WindowsActivation -Computer WS01

# Use explicit credentials
Get-WindowsActivation -Computer WS01 -Credentials (Get-Credential)

# Query multiple computers
Get-WindowsActivation -Computer WS01, WS02, WS03
```

Remote operations use PowerShell CIM sessions. Local sessions use DCOM; remote sessions use WinRM. Ensure WinRM is enabled and reachable for remote computers.

### Activate Windows

```powershell
# Activate the selected Windows product using the currently installed key
Start-WindowsActivation -Verbose

# Install the detected KMS client setup key (GVLK), then activate
Start-WindowsActivation -UseKmsClientKey -Verbose

# Install an explicit product key, then activate in the same operation
Start-WindowsActivation -ProductKey XXXXX-XXXXX-XXXXX-XXXXX-XXXXX

# Activate one product by activation ID
Start-WindowsActivation -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# Activate a remote computer
Start-WindowsActivation -Computer WS01

# Activate a remote computer using explicit credentials
Start-WindowsActivation -Computer WS01 -Credentials (Get-Credential)

# Set a KMS server and port before activation
Start-WindowsActivation -Computer WS01 -KmsServer kms.example.com -KMSServerPort 1688

# Bracket IPv6 when including it with a port
Start-WindowsActivation -KmsServer '[2001:db8::10]:1688'

# Disable KMS host caching before activation
Start-WindowsActivation -Computer WS01 -CacheDisabled
```

`-UseKmsClientKey` installs a known KMS client setup key for the detected Windows edition. `-ProductKey` accepts an explicit key. Both forms then resolve the product registration matching the installed key and attempt activation because this module deliberately combines key installation and activation into one operation.

Do not combine `-ActivationId` with `-ProductKey` or `-UseKmsClientKey`. Windows exposes key installation on `SoftwareLicensingService`, not on an individual licensing product, so that combination cannot safely guarantee that the requested activation ID receives the key. To target an activation ID, install no key in that invocation and use `-ActivationId` by itself.

### Configure the KMS client

```powershell
# Configure a server and the default KMS port without activating
Set-WindowsKmsClient -KmsServer kms01.example.test

# Configure a server with an embedded port
Set-WindowsKmsClient -KmsServer '192.0.2.10:2500'

# Change only the configured port
Set-WindowsKmsClient -Port 2500

# Configure the DNS lookup domain
Set-WindowsKmsClient -LookupDomain activation.example.test

# Disable or enable service-wide KMS host caching
Set-WindowsKmsClient -HostCaching Disabled
Set-WindowsKmsClient -HostCaching Enabled

# Configure an exact licensing product where the provider supports product scope
Set-WindowsKmsClient -KmsServer kms01 -Port 2500 `
    -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

`-KmsServer` accepts a single-label hostname, FQDN, IPv4 address, or bracketed IPv6 address. A port can be embedded in the endpoint or supplied with `-Port`, but not both. Changing a server without specifying a port sets port 1688 so a stale custom port is not retained. `-HostCaching` is service-wide and therefore cannot be combined with `-ActivationId`.

`Start-WindowsActivation -KmsServer ...` preserves the combined configuration-and-activation workflow. `-KMSServerFQDN` remains an accepted parameter name for compatibility.

### Offline activation

```powershell
# Get the offline installation ID
Get-WindowsActivation -Offline

# Apply a confirmation ID returned by phone activation
Start-WindowsActivation -Offline -ConfirmationId 123456-123456-123456-123456-123456-123456-123456-123456-123456

# Apply a confirmation ID to one product
Start-WindowsActivation -Offline -ConfirmationId 123456-123456-123456-123456-123456-123456-123456-123456-123456 -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

The confirmation ID may contain dashes or spaces. The module normalizes it before submitting it.

### Rearm

```powershell
# Rearm Windows when the current state is eligible
Start-WindowsActivation -Rearm

# Rearm one application by application ID
Start-WindowsActivation -Rearm -ApplicationId 11111111-2222-3333-4444-555555555555

# Rearm one licensing product by activation ID
Start-WindowsActivation -Rearm -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

`-ApplicationId` and `-ActivationId` are mutually exclusive and require `-Rearm`. Rearm is a material licensing operation and normally requires a restart before the change takes effect. Run it only when you understand the activation state and the effect on the target system.

### Install and repair licenses

```powershell
# Install one license file on the local computer
Install-WindowsLicense -Path C:\Licenses\example.xrm-ms

# Install multiple license files on multiple computers
Install-WindowsLicense -Computer WS01, WS02 -Credentials (Get-Credential) `
    -Path C:\Licenses\base.xrm-ms, C:\Licenses\edition.xrm-ms

# Reinstall licenses from this computer's Windows OEM and SPP token directories
Repair-WindowsLicense
```

`Install-WindowsLicense` resolves and reads the supplied files on the computer running PowerShell, then sends their contents through CIM to each target. It accepts `.xrm-ms` files only, rejects empty and duplicate paths, attempts every validated file and computer, refreshes licensing after successful installations, and terminates with an aggregate error if any target operation failed.

`Repair-WindowsLicense` is intentionally local-only. It reads the license files from the current Windows installation so licenses from the management computer cannot accidentally be applied to a remote target. It skips filesystem reparse points, processes files in deterministic order, continues past individual failures, and refreshes licensing when at least one file was reinstalled.

### Reset activation-related settings

```powershell
# Uninstall the product key from the selected Windows product
Reset-WindowsActivation -UninstallProductKey

# Uninstall the key from one product
Reset-WindowsActivation -UninstallProductKey -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# Clear the product key from registry storage
Reset-WindowsActivation -ClearProductKeyFromRegistry

# Clear the configured KMS host name and port
Reset-WindowsActivation -ClearKMSSettings

# Clear product-specific KMS client settings
Reset-WindowsActivation -ClearKMSSettings -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# Clear the KMS lookup domain without clearing the configured host and port
Reset-WindowsActivation -ClearKMSLookupDomain

# Clear a product-specific KMS lookup domain
Reset-WindowsActivation -ClearKMSLookupDomain -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# Combine operations
Reset-WindowsActivation -UninstallProductKey -ClearProductKeyFromRegistry -ClearKMSSettings

# Run against a remote computer
Reset-WindowsActivation -Computer WS01 -Credentials (Get-Credential) -UninstallProductKey -ClearProductKeyFromRegistry
```

`-ClearKMSSettings` clears the configured KMS host name and port. It preserves a configured KMS lookup domain, matching `/ckms` behavior. Use `-ClearKMSLookupDomain` to clear the domain independently. With `-ActivationId`, either switch invokes the product-scoped KMS client methods.

## Comparison with slmgr.vbs

The following table compares the current `slmgr-ps` implementation with documented `slmgr.vbs` options.

Microsoft documentation: [Slmgr.vbs options for obtaining volume activation information](https://learn.microsoft.com/en-us/windows-server/get-started/activation-slmgr-vbs-options)

### General command shape

```cmd
slmgr.vbs [<ComputerName> [<User> <Password>]] [<Options>]
```

| `slmgr.vbs` capability   | `slmgr-ps` equivalent           |                Status | Notes                                                                             |
| ------------------------ | ------------------------------- | --------------------: | --------------------------------------------------------------------------------- |
| Local execution          | Default `-Computer localhost`   |             Supported | Local CIM sessions use DCOM.                                                      |
| Remote computer          | `-Computer WS01`                |             Supported | Remote CIM sessions use WinRM, not the old `slmgr.vbs` DCOM/WMI command shape.    |
| Remote user and password | `-Credentials (Get-Credential)` | Supported differently | `slmgr-ps` uses `PSCredential` instead of exposing passwords on the command line. |
| Multiple computers       | `-Computer WS01, WS02`          |             Supported | This is a PowerShell-native improvement over the single-target `slmgr.vbs` style. |

### Global options

| `slmgr.vbs` option     | `slmgr-ps` equivalent                      |          Status | Notes                                                                                                   |
| ---------------------- | ------------------------------------------ | --------------: | ------------------------------------------------------------------------------------------------------- |
| `/ipk <ProductKey>`    | `Start-WindowsActivation -ProductKey <ProductKey>` | Supported differently | Installs the supplied key and immediately attempts activation in the same operation.                |
| `/ato`                 | `Start-WindowsActivation`                        | Supported | Activates the selected Windows licensing product.                                                  |
| `/ato <Activation ID>` | `Start-WindowsActivation -ActivationId <ActivationId>` | Supported | Resolves and activates the exact SPP product.                                                   |
| `/dli`                 | `Get-WindowsActivation`                    |       Supported | Returns basic information for the selected Windows licensing product.                                   |
| `/dli <Activation ID>` | `Get-WindowsActivation -ActivationId <ActivationId>` | Supported | Returns basic information for the exact SPP product.                                           |
| `/dli all`             | `Get-WindowsActivation -All`                        | Supported | Returns basic information for every SPP product.                                                |
| `/dlv`                 | `Get-WindowsActivation -Extended`          |       Supported | Returns extended information for the selected Windows licensing product.                                |
| `/dlv <Activation ID>` | `Get-WindowsActivation -Extended -ActivationId <ActivationId>` | Supported | Returns extended information for the exact SPP product.                              |
| `/dlv all`             | `Get-WindowsActivation -Extended -All`                        | Supported | Returns extended information for every SPP product.                                   |
| `/xpr`                 | `Get-WindowsActivation -Expiry`            |       Supported | Returns expiry status for the selected Windows licensing product.                                       |
| `/xpr <Activation ID>` | `Get-WindowsActivation -Expiry -ActivationId <ActivationId>` | Supported | Returns expiry information for the exact SPP product.                                    |

### Advanced options

| `slmgr.vbs` option                       | `slmgr-ps` equivalent                                                |          Status | Notes                                                                                 |
| ---------------------------------------- | -------------------------------------------------------------------- | --------------: | ------------------------------------------------------------------------------------- |
| `/cpky`                                  | `Reset-WindowsActivation -ClearProductKeyFromRegistry`               |       Supported | Clears the product key from registry storage through `SoftwareLicensingService`.      |
| `/ilc <license_file>`                    | `Install-WindowsLicense -Path <license_file>`                         | Supported differently | Reads the controller-side `.xrm-ms` file and installs its content through CIM.         |
| `/rilc`                                  | `Repair-WindowsLicense`                                               | Supported locally | Reinstalls `.xrm-ms` files from the local Windows OEM and SPP token directories.       |
| `/rearm`                                 | `Start-WindowsActivation -Rearm`                                     |       Supported | Resets activation state where supported by Windows.                                   |
| `/rearm-app <Application ID>`            | `Start-WindowsActivation -Rearm -ApplicationId <ApplicationId>`       |       Supported | Rearms the exact application through `SoftwareLicensingService`.                       |
| `/rearm-sku <Activation ID>`             | `Start-WindowsActivation -Rearm -ActivationId <ActivationId>`         |       Supported | Resolves and rearms the exact licensing product.                                       |
| `/upk`                                   | `Reset-WindowsActivation -UninstallProductKey`                       |       Supported | Uninstalls the product key from the selected Windows licensing product.               |
| `/upk <Activation ID>`                   | `Reset-WindowsActivation -UninstallProductKey -ActivationId <ActivationId>` | Supported | Uninstalls the key from the exact SPP product.                          |
| `/dti`                                   | `Get-WindowsActivation -Offline`                                     |       Supported | Returns the offline installation ID for the selected Windows licensing product.       |
| `/dti <Activation ID>`                   | `Get-WindowsActivation -Offline -ActivationId <ActivationId>`        | Supported | Returns the offline installation ID for the exact SPP product.                        |
| `/atp <Confirmation ID>`                 | `Start-WindowsActivation -Offline -ConfirmationId <Confirmation ID>` |       Supported | Applies a confirmation ID to the selected Windows licensing product.                  |
| `/atp <Confirmation ID> <Activation ID>` | `Start-WindowsActivation -Offline -ConfirmationId <ConfirmationId> -ActivationId <ActivationId>` | Supported | Applies the confirmation ID to the exact SPP product. |

### KMS client options

| `slmgr.vbs` option                    | `slmgr-ps` equivalent                                                 |          Status | Notes                                                                                                                     |
| ------------------------------------- | --------------------------------------------------------------------- | --------------: | ------------------------------------------------------------------------------------------------------------------------- |
| `/skms <Name[:Port]>`                 | `Set-WindowsKmsClient -KmsServer <Name[:Port]>`                        | Supported | Accepts hostnames, FQDNs, IPv4, and bracketed IPv6. Use `-Port` alone for the `:Port` form.                                |
| `/skms <Name[:Port]> <Activation ID>` | Add `-ActivationId <ActivationId>` to the command above                | Supported | Applies the endpoint to the exact licensing product. `Start-WindowsActivation` can configure and activate in one call.    |
| `/skms-domain <FQDN>`                 | `Set-WindowsKmsClient -LookupDomain <FQDN>`                            | Supported | Configures the service-wide KMS DNS lookup domain.                                                                         |
| `/skms-domain <FQDN> <Activation ID>` | Add `-ActivationId <ActivationId>` to the command above                | Supported | Configures the lookup domain on the exact licensing product.                                                               |
| `/ckms`                               | `Reset-WindowsActivation -ClearKMSSettings`                           |       Supported | Clears the configured KMS host name and port while preserving the KMS lookup domain.                                      |
| `/ckms <Activation ID>`               | `Reset-WindowsActivation -ClearKMSSettings -ActivationId <ActivationId>` | Supported | Clears product-specific KMS client host and port settings.                         |
| `/ckms-domain`                        | `Reset-WindowsActivation -ClearKMSLookupDomain`                       | Supported | Clears the lookup domain without clearing the configured host and port.                                                   |
| `/skhc`                               | `Set-WindowsKmsClient -HostCaching Enabled`                           | Supported | Enables service-wide KMS host caching.                                                                                     |
| `/ckhc`                               | `Set-WindowsKmsClient -HostCaching Disabled`                          | Supported | Disables service-wide KMS host caching. `Start-WindowsActivation -CacheDisabled` remains available for combined use.       |

### KMS server configuration options

| `slmgr.vbs` option                       | `slmgr-ps` equivalent |          Status | Notes                                                                             |
| ---------------------------------------- | --------------------- | --------------: | --------------------------------------------------------------------------------- |
| `/sai <Interval>`                        | None                  | Not implemented | KMS host activation interval configuration is not currently supported.            |
| `/sri <Interval>`                        | None                  | Not implemented | KMS host renewal interval configuration is not currently supported.               |
| `/sprt <Port>`                           | None                  | Not implemented | KMS host listening-port configuration is not currently supported.                 |
| `/sdns`                                  | None                  | Not implemented | KMS host DNS publishing enable is not currently supported.                        |
| `/cdns`                                  | None                  | Not implemented | KMS host DNS publishing disable is not currently supported.                       |
| `/spri`                                  | None                  | Not implemented | KMS host normal-priority configuration is not currently supported.                |
| `/cpri`                                  | None                  | Not implemented | KMS host low-priority configuration is not currently supported.                   |
| `/act-type`                              | None                  | Not implemented | Volume activation type clearing is not currently supported.                       |
| `/act-type <0\|1\|2\|3>`                 | None                  | Not implemented | Global volume activation type configuration is not currently supported.           |
| `/act-type <0\|1\|2\|3> <Activation ID>` | None                  | Not implemented | Product-specific volume activation type configuration is not currently supported. |

### Token-based activation options

| `slmgr.vbs` option                    | `slmgr-ps` equivalent |          Status | Notes                                                            |
| ------------------------------------- | --------------------- | --------------: | ---------------------------------------------------------------- |
| `/lil`                                | None                  | Not implemented | Issuance-license listing is not currently supported.             |
| `/ril <ILID> <ILvID>`                 | None                  | Not implemented | Issuance-license removal is not currently supported.             |
| `/ltc`                                | None                  | Not implemented | Token activation certificate listing is not currently supported. |
| `/fta <Certificate Thumbprint>`       | None                  | Not implemented | Token activation is not currently supported.                     |
| `/fta <Certificate Thumbprint> <PIN>` | None                  | Not implemented | Token activation with PIN is not currently supported.            |
| `/stao`                               | None                  | Not implemented | Deprecated in modern Windows; use `/act-type` in `slmgr.vbs`.    |
| `/ctao`                               | None                  | Not implemented | Deprecated in modern Windows; use `/act-type` in `slmgr.vbs`.    |

### Active Directory-based activation options

| `slmgr.vbs` option                                                                  | `slmgr-ps` equivalent |          Status | Notes                                                                |
| ----------------------------------------------------------------------------------- | --------------------- | --------------: | -------------------------------------------------------------------- |
| `/ad-activation-online <Product Key>`                                               | None                  | Not implemented | AD-based activation is not currently supported.                      |
| `/ad-activation-online <Product Key> <Activation Object name>`                      | None                  | Not implemented | AD activation object naming is not currently supported.              |
| `/ad-activation-get-iid <Product Key>`                                              | None                  | Not implemented | AD phone activation IID generation is not currently supported.       |
| `/ad-activation-apply-cid <Product Key> <Confirmation ID>`                          | None                  | Not implemented | AD offline activation confirmation is not currently supported.       |
| `/ad-activation-apply-cid <Product Key> <Confirmation ID> <Activation Object name>` | None                  | Not implemented | AD offline activation with object naming is not currently supported. |
| `/ao-list`                                                                          | None                  | Not implemented | AD activation-object listing is not currently supported.             |
| `/del-ao <AO_DN>` or `/del-ao <AO_RDN>`                                             | None                  | Not implemented | AD activation-object deletion is not currently supported.            |

## Design differences from slmgr.vbs

`slmgr-ps` is not a direct port of the command-line interface. It uses PowerShell conventions instead.

- It accepts arrays of computer names.
- It uses `PSCredential` rather than command-line password arguments.
- It uses CIM sessions.
- Remote execution uses WinRM.
- It returns PowerShell objects for reporting commands and stable operation-result objects for mutating commands.
- It supports PowerShell pipeline-friendly usage.
- It includes KMS client setup keys for supported Windows editions.
- It combines explicit product-key installation and activation in one command.
- It installs license files on multiple targets from controller-side paths.
- It keeps system-license repair local to prevent cross-machine license-file use.
- It works without Windows Script Host, so environments that block `cscript.exe` and `wscript.exe` can still perform supported activation workflows.

## Current limitations

The following areas are intentionally not presented as supported yet:

- KMS server configuration, including listening port, DNS publishing, intervals, and process priority.
- Remote system-license repair; `Repair-WindowsLicense` is local-only by design.
- Token-based activation.
- Active Directory-based activation.
- `slmgr.vbs` command-line syntax compatibility.

## Security notes

Avoid passing secrets directly on the command line. `slmgr.vbs` supports a command shape that includes username and password as arguments. `slmgr-ps` uses `PSCredential` instead, which is more appropriate for PowerShell usage and avoids exposing passwords in command-line history or process listings.

An explicit `-ProductKey` remains plain command-line input and may be retained in PowerShell history. Protect shell history and automation logs, and avoid recording the full invocation in shared diagnostics.

For calls containing multiple computers or license files, mutating commands attempt every applicable item before reporting collected failures. Successful targets emit normal operation-result objects. Failed targets are represented in the final `LicensingBatchFailed` error, so automation must treat the invocation as failed even when later operations succeeded.

For remote execution, prefer properly configured WinRM. Where appropriate, use HTTPS for WinRM. See Microsoft documentation on [WinRM security](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security).

## Troubleshooting

Use `-Verbose` for operational detail:

```powershell
Get-WindowsActivation -Verbose
Install-WindowsLicense -Path C:\Licenses\example.xrm-ms -Verbose
Repair-WindowsLicense -Verbose
Set-WindowsKmsClient -KmsServer kms01.example.test -Verbose
Start-WindowsActivation -Verbose
Reset-WindowsActivation -Verbose -ClearKMSSettings
```

Use `-Debug` when investigating lower-level behavior:

```powershell
Start-WindowsActivation -Debug
```

The module can be imported without elevation for read-only commands. Mutating operations should be run with credentials that have the required privileges on the target computer.

## Contributing

The long-term goal is to cover more of the practical `slmgr.vbs` workflow surface while keeping the PowerShell interface safer and more maintainable than the original VBScript command style.

Useful contribution areas include:

- Adding KMS server configuration workflows after the client capability path is complete.
- Adding tests for CIM provider compatibility across supported Windows versions.
- Improving documentation and examples.

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for pull request guidance.
