# Validation and Support Matrix

See [README.md](../README.md) for installation and usage. See [USAGE.md](USAGE.md) for command examples.

The table below distinguishes automated verification from capabilities that still require environment-specific integration testing. Passing CI does not by itself establish support for every Windows release or every licensing topology. The stable 1.x interface inventory is defined once in `tests/PublicContract.psd1` and consumed by both Pester and CI.

| Area | Current validation |
| --- | --- |
| Windows PowerShell 5.1 | Pester runs in CI on `windows-latest`. |
| PowerShell 7 | Pester runs in CI using the current PowerShell 7 available on `windows-latest`. Older PowerShell 7 baselines are not separately matrix-tested. |
| Module manifest and exports | Validated in CI against `tests/PublicContract.psd1`. |
| Public 1.x parameters and aliases | Pinned by `PublicContractStability.Tests.ps1` to detect accidental breaking drift. |
| `ShouldProcess` mutation contract | Pinned for mutating public commands by the declarative public contract. |
| SPP provider contracts | Live CIM class, property, method, and argument checks run where the GitHub Windows runner exposes the relevant provider surface. Optional provider fields are not treated as universally available. |
| Local CIM/DCOM workflows | Available in the opt-in integration matrix and covered by unit/provider tests. |
| Remote WinRM and explicit credentials | Available in the opt-in integration matrix when a remote target is supplied. |
| KMS client operations | Covered by unit and provider-contract tests. |
| KMS host operations | Read-only host validation is available in the integration matrix. Real mutation requires an isolated host and explicit mutation opt-in. |
| Token issuance licenses | Listing and exact ILID/ILVID removal are covered by provider-contract and unit tests. Certificate/PIN activation remains unsupported. |
| Active Directory activation | Read-only activation-object enumeration is available in the integration matrix. Publication, privilege-failure, duplicate, and deletion paths still require a dedicated AD lab. |

Standard CI explicitly excludes tests tagged `Integration`. Run the read-only integration matrix on an appropriate Windows system with:

```powershell
./tests/Integration/Invoke-IntegrationMatrix.ps1
```

Remote WinRM, explicit credentials, KMS-host reads, and Active Directory reads can be enabled by supplying their targets:

```powershell
./tests/Integration/Invoke-IntegrationMatrix.ps1 `
    -RemoteComputer WS01 `
    -Credential (Get-Credential) `
    -KmsHost KMS01 `
    -DirectoryServer dc01.example.test `
    -DirectoryCredential (Get-Credential)
```

Destructive integration tests remain excluded unless `-AllowMutation` is supplied. The current destructive probe writes a KMS host's existing activation interval back to the same value and verifies the provider read-back result. It still invokes a real mutating method and should only be run in an isolated validation environment.

No Windows version outside an actually exercised environment should be inferred to be fully validated merely because its SPP provider exposes similarly named CIM members.
