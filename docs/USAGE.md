# Usage Guide

Full command-by-command examples for `slmgr-ps`. See [README.md](../README.md) for installation, the validation matrix, security notes, and the slmgr.vbs comparison.

## Get Windows activation information

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

Extended output includes the raw numeric and readable license status, status reason, grace period, evaluation end date, Windows/application/SKU rearm counts, trusted time, SPP service version, client-machine ID, KMS-host status, volume activation and renewal intervals, configured activation-type policy, last volume activation type, token activation state, Active Directory activation-object metadata, configured and discovered KMS host and port values, the KMS lookup domain, and service-wide host-caching state when the provider exposes them. Unset provider dates are returned as `$null`.

## Work with remote computers

```powershell
# Basic license information from a remote computer
Get-WindowsActivation -Computer WS01

# Use explicit credentials
Get-WindowsActivation -Computer WS01 -Credentials (Get-Credential)

# Query multiple computers
Get-WindowsActivation -Computer WS01, WS02, WS03
```

Remote CIM operations use PowerShell CIM sessions. Local sessions use DCOM; remote sessions use WinRM. Ensure WinRM is enabled and reachable for remote computers. Active Directory activation-object commands use the ActiveDirectory PowerShell module and directory connectivity instead of the CIM remote-execution path.

## Activate Windows

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

## Configure the KMS client

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

## Configure and inspect a KMS host

```powershell
# Report KMS host state and request counters
Get-WindowsKmsHost

# Query a remote KMS host
Get-WindowsKmsHost -Computer KMS01 -Credentials (Get-Credential)

# Configure the listening port
Set-WindowsKmsHost -ListeningPort 1688

# Clear an explicit listening-port override and return to the documented default
Set-WindowsKmsHost -ClearListeningPort

# Set the pre-activation and renewal intervals in minutes
Set-WindowsKmsHost -ActivationInterval 120 -RenewalInterval 10080

# Enable or disable DNS publishing
Set-WindowsKmsHost -DnsPublishing Enabled
Set-WindowsKmsHost -DnsPublishing Disabled

# Run the KMS service at normal or low priority
Set-WindowsKmsHost -Priority Normal
Set-WindowsKmsHost -Priority Low

# Apply several host settings in one invocation
Set-WindowsKmsHost -ListeningPort 1688 `
    -ActivationInterval 120 `
    -RenewalInterval 10080 `
    -DnsPublishing Enabled `
    -Priority Normal
```

`Get-WindowsKmsHost` requires the target to report itself as an enabled KMS host. It returns the current listening port, DNS-publishing and priority state, activation and renewal intervals, KMS client counts, KMS product-key ID, activation-disabled state when that optional provider property exists, and documented request counters. A cleared listening-port override is reported separately from the effective default port 1688. Current interval values are reported alongside the documented defaults of 120 minutes for activation and 10,080 minutes for renewal because SPP does not expose a separate “configured override” flag for those interval properties.

`Set-WindowsKmsHost` validates host capability before invoking any host-only method. Listening ports must be between 1 and 65535; activation and renewal intervals must be between 15 and 43,200 minutes. Each requested setting is applied in deterministic order and re-read from `SoftwareLicensingService`; successful settings return `Verified`. Combined settings are not transactional, so a later failure does not roll back earlier successful changes. The final aggregate error preserves those partial-completion results.

KMS host mutations use `ShouldProcess` with high confirmation impact. Client configuration remains in `Set-WindowsKmsClient`; host configuration remains in `Set-WindowsKmsHost` so the two roles are not conflated.

## Configure volume activation policy

```powershell
# Allow any supported volume activation mechanism
Set-WindowsActivationType -ActivationType Any

# Restrict activation to Active Directory, KMS, or token activation
Set-WindowsActivationType -ActivationType ActiveDirectory
Set-WindowsActivationType -ActivationType Kms
Set-WindowsActivationType -ActivationType Token

# Apply the policy to an exact licensing product
Set-WindowsActivationType -ActivationType Kms `
    -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

`Any` clears the configured activation-type restriction. The restricted values map to the documented Software Protection Platform activation-type values. Policy changes return the common structured mutation result and report `ProviderAccepted` because the provider call does not itself return an authoritative post-state object.

## Offline activation

```powershell
# Get the offline installation ID
Get-WindowsActivation -Offline

# Apply a confirmation ID returned by phone activation
Start-WindowsActivation -Offline -ConfirmationId 123456-123456-123456-123456-123456-123456-123456-123456-123456

# Apply a confirmation ID to one product
Start-WindowsActivation -Offline -ConfirmationId 123456-123456-123456-123456-123456-123456-123456-123456-123456 -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

The confirmation ID may contain dashes or spaces. The module normalizes it before submitting it.

## Token activation issuance licenses

```powershell
# List installed token activation issuance licenses
Get-WindowsTokenActivationLicense

# Query a remote computer
Get-WindowsTokenActivationLicense -Computer WS01 -Credentials (Get-Credential)

# Remove one exact issuance license
Remove-WindowsTokenActivationLicense `
    -ILID 11111111-2222-3333-4444-555555555555 `
    -ILVID 7
```

Issuance-license removal requires the exact ILID and ILVID pair. The module calls the documented `SoftwareLicensingTokenActivationLicense.Uninstall()` method and verifies that the exact license is no longer returned by the provider. Token certificate enumeration and certificate/PIN-driven activation are not implemented because the required end-to-end workflow is not sufficiently documented through public interfaces.

## Active Directory-based activation

Active Directory activation-object workflows require the ActiveDirectory PowerShell module and access to the target forest. Product keys and confirmation IDs are sensitive input and are not included in normal result objects.

```powershell
# Generate the installation ID for an offline AD activation workflow
Get-WindowsADActivationInstallationId -ProductKey XXXXX-XXXXX-XXXXX-XXXXX-XXXXX

# Create and publish an activation object online
New-WindowsADActivationObject `
    -ProductKey XXXXX-XXXXX-XXXXX-XXXXX-XXXXX `
    -ActivationObjectName 'Windows Activation'

# Complete the offline workflow after receiving a confirmation ID
New-WindowsADActivationObject `
    -ProductKey XXXXX-XXXXX-XXXXX-XXXXX-XXXXX `
    -ConfirmationId 123456-123456-123456-123456-123456-123456-123456-123456-123456 `
    -ActivationObjectName 'Windows Activation'

# List activation objects or resolve one object
Get-WindowsADActivationObject
Get-WindowsADActivationObject -Name 'Windows Activation'
Get-WindowsADActivationObject -DistinguishedName 'CN=example,CN=Activation Objects,CN=Microsoft SPP,CN=Services,CN=Configuration,DC=example,DC=test'

# Remove an exact activation object
Remove-WindowsADActivationObject `
    -DistinguishedName 'CN=example,CN=Activation Objects,CN=Microsoft SPP,CN=Services,CN=Configuration,DC=example,DC=test'
```

`New-WindowsADActivationObject` requires an explicit activation-object name so the module can reject duplicates before mutation and verify the exact object afterward. Directory context is resolved through the ActiveDirectory module; the activation-object container is queried from the directory instead of constructing an LDAP distinguished name by concatenation. Deletion accepts only an exact distinguished name, uses high-impact confirmation, and verifies that the object disappeared.

Use `-DirectoryServer` and `-DirectoryCredential` when explicit directory targeting is required.

## Rearm

```powershell
# Rearm Windows when the current state is eligible
Start-WindowsActivation -Rearm

# Rearm one application by application ID
Start-WindowsActivation -Rearm -ApplicationId 11111111-2222-3333-4444-555555555555

# Rearm one licensing product by activation ID
Start-WindowsActivation -Rearm -ActivationId aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

`-ApplicationId` and `-ActivationId` are mutually exclusive and require `-Rearm`. Rearm is a material licensing operation and normally requires a restart before the change takes effect. Run it only when you understand the activation state and the effect on the target system.

## Install and repair licenses

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

## Reset activation-related settings

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

## Operation results and errors

Mutating commands emit a `slmgr-ps.LicensingOperationResult` when they use the common licensing mutation contract. The contract is used across activation, rearm, KMS client and host configuration, activation-type policy, reset, license installation, system-license repair, token issuance-license removal, and Active Directory activation-object mutation.

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

For multi-computer operations, the module continues with later targets when it is safe to do so. If any target or individual KMS host setting fails, the command terminates after the applicable batch with a `LicensingBatchFailed` error. Its `TargetObject` contains the failed `LicensingOperationResult` objects, and detailed errors are retained in exception data. Successful settings are not rolled back when a later independent KMS host setting fails.
