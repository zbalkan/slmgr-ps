# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.7.0] - 2026-09-13

### Added

* Added `Get-WindowsTokenActivationLicense` for listing token activation issuance licenses.
* Added `Remove-WindowsTokenActivationLicense` for removing an exact issuance license by `ILID` and `ILVID`.
* Added documented `SoftwareLicensingTokenActivationLicense` provider support, including the `Uninstall()` method.
* Added token activation ILID, ILVID, grant number, certificate thumbprint, and additional information to extended activation reporting.
* Added local and remote token-license management with credential support.

### Changed

* Token-license removal now uses the standard structured licensing result and batch error contracts.
* Token-license removal verifies success by re-querying the exact `ILID` and `ILVID` pair after uninstall.
* The module now exports nine public commands.

### Security

* Token activation PIN handling and certificate-driven activation are not implemented because the required workflow is not sufficiently documented through public interfaces.

## [1.6.0] - 2026-09-13

### Added

* Added `Set-WindowsActivationType` for configuring volume activation policy.
* Added support for `Any`, `ActiveDirectory`, `Kms`, and `Token` activation policies.
* Added service-wide and activation-ID-scoped activation policy configuration.
* Added configured activation policy and last-used volume activation type to extended activation reporting.
* Added Software Protection Platform contracts for `SetVLActivationTypeEnabled` and `ClearVLActivationTypeEnabled`.

### Changed

* Activation policy changes now use the standard `slmgr-ps.LicensingOperationResult` contract and batch error handling introduced in 1.5.0.
* `Any` clears the activation-type restriction, while restricted policies use the provider-defined activation type values.
* The module now exports `Set-WindowsActivationType` as its seventh public command.

## [1.5.0] - 2026-09-13

### Added

* Added a stable `slmgr-ps.LicensingOperationResult` contract for mutating commands.
* Added explicit `Verified`, `ProviderAccepted`, `NotVerifiable`, and `Failed` verification states.
* Added stable operation identifiers for activation, rearm, KMS configuration, reset, license installation, and repair.
* Added hexadecimal SPP and CIM provider error codes when available.
* Expanded extended activation reporting with numeric and readable license status, status reason, evaluation end date, grace and rearm data, service version, client-machine ID, KMS-host state, and activation and renewal intervals.

### Changed

* Mutating commands now return one structured operation result for each attempted computer instead of remaining silent on success.
* Batch operations now report failures through one aggregate `LicensingBatchFailed` error containing the structured failed-target results and underlying error information.
* Rearm operations now explicitly report restart requirements and provider-acceptance state.

### Fixed

* Preserved unset provider dates as `$null` instead of substituting artificial minimum dates.
* Stopped reporting generic CLR exception values as licensing error codes when no SPP or CIM provider code is available.
* Removed duplicate per-target error emission before the final aggregate batch error.
* Separated service-wide Windows rearm counts from product-level application and SKU rearm counts.

## [1.4.0] - 2026-09-13

### Added

* Added `Set-WindowsKmsClient` for standalone KMS client configuration without requiring an activation attempt.
* Added standalone KMS endpoint, port, DNS lookup-domain, and host-caching configuration.
* Added service-wide and activation-ID-scoped KMS client settings where supported by the Software Protection Platform provider.
* Added `Reset-WindowsActivation -ClearKMSLookupDomain` for clearing the DNS lookup domain independently of the configured KMS host and port.
* Added configured and discovered KMS client state to extended activation output.
* Added validation for hostnames, FQDNs, IPv4 addresses, bracketed IPv6 addresses, embedded ports, DNS lookup domains, and port ranges.

### Changed

* `Start-WindowsActivation` now reuses the common KMS endpoint validation while retaining the combined configure-and-activate workflow.
* Setting a KMS server without an explicit port now configures the default port `1688`, preventing a stale custom port from being retained.
* KMS input validation now occurs before CIM sessions are opened.

### Fixed

* Corrected KMS host-caching calls to pass the provider-required `DisableCaching` argument.
* Preserved the existing host-and-port-only behaviour of `-ClearKMSSettings` when independent lookup-domain clearing was added.

## [1.3.0] - 2026-09-13

### Added

* Added `Install-WindowsLicense` for installing one or more `.xrm-ms` license files on local or remote computers.
* Added `Repair-WindowsLicense` for reinstalling licenses from the local Windows OEM and Software Protection Platform token directories.
* Added application-level rearm through `Start-WindowsActivation -Rearm -ApplicationId`.
* Added SKU-level rearm through `Start-WindowsActivation -Rearm -ActivationId`.
* Added `InstallLicense`, `ReArmApp`, and `ReArmSku` support to the internal Software Protection Platform provider contract.
* Added tests for routing, cleanup, `ShouldProcess`, partial failures, file validation, targeted rearm, and public exports.

### Changed

* License files are validated and read locally before CIM sessions are opened.
* Remote license installation now sends validated license contents through CIM instead of requiring matching filesystem paths on remote computers.
* System-license repair is intentionally local-only and processes discovered licenses in deterministic order.
* Mutating license-maintenance operations continue across individual file or computer failures and terminate after processing if any operation failed.

## [1.2.0] - 2026-09-13

### Added

* Added explicit product-key installation followed by activation in one command.
* Added activation-ID targeting for license queries, online activation, offline activation, product-key removal, and KMS client settings.
* Added `-All` enumeration for basic and extended license information.
* Added product and application identifiers to license-information output.
* Added product-specific KMS client configuration and reset operations.

### Changed

* Product selection now distinguishes read, default mutation, activation-ID, partial-key, and all-product queries.
* Product-key installation now resolves the resulting registration deterministically and verifies the final activation state using its activation ID.
* Activation and reset batches now continue across target failures and terminate after processing if any target failed.
* Software Protection Platform method invocation now validates the provider class associated with each method.

### Fixed

* Rejected ambiguous product-key and activation-ID combinations before opening a CIM session.
* Prevented mutating operations from silently selecting a product when the selection is missing or ambiguous.
* Changed targeted reset ordering so KMS settings are cleared before uninstalling the selected product key.

## [1.1.2] - 2026-09-11

### Fixed

* Corrected the publishing script to handle both `main` and `master` branch checks.

## [1.1.1] - 2026-09-11

### Changed

* Allowed non-elevated module import so read-only commands can run without administrative privileges.
* Preserved the caller's error-action preference instead of overriding it.
* Activation batches now continue across individual computer failures before reporting a terminating batch failure.

### Fixed

* Corrected product-key registry clearing to use `SoftwareLicensingService`.
* Corrected KMS reset to clear both the configured host and port while preserving the lookup domain.
* Added Software Protection Platform method-ownership validation.
* Added final-state verification for offline activation.
* Prevented offline activation from reporting success when the final licensing state could not confirm the operation.
* Added Software Protection Platform class-contract, CIM-session, and failure-path tests.

## [1.1.0] - 2026-06-14

### Added

* Added `Reset-WindowsActivation`.
* Added product-key uninstallation through `-UninstallProductKey`.
* Added product-key removal from registry storage through `-ClearProductKeyFromRegistry`.
* Added KMS client reset through `-ClearKMSSettings`.
* Added support for combining reset operations in a single invocation.
* Added local and remote reset operations using `-Computer` and `-Credentials`.
* Added `ShouldProcess`, `-WhatIf`, and `-Confirm` support for reset operations.
* Added Pester coverage for the new reset command.

## [1.0.0] - 2026-06-14

### Added

* Established the first stable release of the PowerShell module.
* Added `Get-WindowsActivation` for basic and extended Windows licensing information.
* Added license-expiration reporting.
* Added offline installation-ID retrieval.
* Added `Start-WindowsActivation` for Windows activation.
* Added online KMS activation.
* Added offline activation using a confirmation ID.
* Added Windows activation rearm.
* Added optional KMS client setup-key installation before activation.
* Added KMS server and port selection during activation.
* Added KMS host-caching control.
* Added local and remote operation through CIM sessions and PowerShell credentials.
