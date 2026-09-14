# slmgr-ps

A partial PowerShell alternative for common `slmgr.vbs` workflows.

`slmgr-ps` covers common Windows licensing and activation operations: status, online/offline activation, license install/repair, rearm, product-key removal, KMS client/host configuration, activation-type policy, token issuance-license management, and Active Directory-based activation. It is not a parameter-compatible or feature-complete replacement for `slmgr.vbs`.

> Microsoft now provides the official [OSLicense PowerShell module](https://learn.microsoft.com/en-gb/powershell/module/oslicense/?view=windowsserver2025-ps). New deployments should generally prefer OSLicense where it is available. `slmgr-ps` remains an independent implementation with no OSLicense dependency — see [docs/OSLICENSE.md](https://github.com/zbalkan/slmgr-ps/blob/main/docs/OSLICENSE.md).

## About this module

I disable [Windows Script Host](https://www.f-secure.com/en/articles/how-to-disable-windows-script-host) (blocking `cscript`/`wscript`) and redirect `.vbs` to Notepad as a hardening measure, which also breaks `slmgr.vbs`. This module reimplements the workflows I needed during a Windows 7 to Windows 10 migration, based on an earlier [gist script](https://gist.github.com/zbalkan/4ba92656a3a8387e6b220bcf8fcd5fc6), packaged for the [PowerShell Gallery](https://www.powershellgallery.com/packages/slmgr-ps).

![Blocked WSH](https://github.com/zbalkan/slmgr-ps/raw/main/images/blocked.png "Blocked WSH")
![.vbs extension is not an executable](https://github.com/zbalkan/slmgr-ps/raw/main/images/notepad.png ".vbs extension is not an executable.")

## Installation

```powershell
Install-Module slmgr-ps
```

## Validation and support matrix

CI runs Pester on Windows PowerShell 5.1 and PowerShell 7, and validates the module manifest, exported functions, and public parameter/`ShouldProcess` contract against `tests/PublicContract.psd1`. An opt-in integration matrix (`./tests/Integration/Invoke-IntegrationMatrix.ps1`) covers remote WinRM, KMS-host reads, and Active Directory reads against real targets.

See [docs/VALIDATION.md](https://github.com/zbalkan/slmgr-ps/blob/main/docs/VALIDATION.md) for the full validation table and integration-matrix usage.

## Basic usage

`slmgr-ps` exports commands for activation status/activation, KMS client and host configuration, volume activation-type policy, offline and rearm workflows, license install/repair, token issuance-license management, and Active Directory-based activation. Every command accepts `-Computer` (with `-Credentials`); mutating commands return a `slmgr-ps.LicensingOperationResult`.

```powershell
Get-WindowsActivation                               # similar to slmgr.vbs /dli
Start-WindowsActivation -Verbose                     # activate with the installed key
Set-WindowsKmsClient -KmsServer kms01.example.test   # configure a KMS server
```

See [docs/USAGE.md](https://github.com/zbalkan/slmgr-ps/blob/main/docs/USAGE.md) for the full command-by-command reference and the `LicensingOperationResult` contract.

## Comparison with slmgr.vbs

`slmgr-ps` maps most documented `slmgr.vbs` options onto PowerShell-native commands, deliberately excluding `/ltc`/`/fta` (token certificate/PIN activation) and RDN-only Active Directory activation-object deletion.

See [docs/slmgr-comparison.md](https://github.com/zbalkan/slmgr-ps/blob/main/docs/slmgr-comparison.md) for the full option-by-option mapping and the PowerShell-convention design differences from `slmgr.vbs`.

## Current limitations

- Remote system-license repair; `Repair-WindowsLicense` is local-only by design.
- Token activation certificate listing and certificate/PIN-driven activation.
- RDN-only Active Directory activation-object deletion; an exact distinguished name is required.
- Active Directory operations require the ActiveDirectory PowerShell module and forest connectivity/privileges.
- KMS host mutations require `IsKeyManagementServiceMachine = 1`; still needs real-host integration testing.
- Full cross-version Windows/PowerShell integration coverage.
- `slmgr.vbs` command-line syntax compatibility.

## Security notes

`slmgr-ps` uses `PSCredential` instead of `slmgr.vbs`'s command-line username/password, avoiding exposure in shell history or process listings. Explicit product keys and confirmation IDs remain plain command-line input, though, and may be retained in PowerShell history — protect shell history and automation logs accordingly; the module never echoes them into result objects or error metadata.

Token PIN handling is deliberately unsupported rather than routed through undocumented interfaces. Active Directory activation-object deletion and KMS host mutation both use high-impact `ShouldProcess`; KMS host mutation additionally refuses targets that don't identify as enabled KMS hosts.

Mutating commands attempt every target/file before reporting collected failures as a `LicensingBatchFailed` error, so treat the invocation as failed even when some targets succeeded. For remote execution, prefer WinRM over HTTPS — see Microsoft's [WinRM security guidance](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security).

## Troubleshooting

Use `-Verbose` for operational detail and `-Debug` for lower-level behavior:

```powershell
Get-WindowsActivation -Verbose
Start-WindowsActivation -Debug
```

The module can be imported without elevation for read-only commands. Mutating operations need credentials with the required privileges on the target; Active Directory operations need matching directory permissions.

## Contributing

`slmgr-ps` is approaching feature completion and stays within 1.x Semantic Versioning; no 2.x release is currently planned. Useful contribution areas: real KMS host integration tests, CIM provider compatibility across Windows versions, Active Directory integration tests, and expanding the validation matrix without changing the 1.x command surface.

See [CONTRIBUTING.MD](CONTRIBUTING.MD) for pull request guidance.
