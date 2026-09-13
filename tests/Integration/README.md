# Integration test matrix

The integration suite is intentionally separate from normal CI. Standard CI excludes tests tagged `Integration`; these tests are for controlled Windows environments where real CIM, WinRM, KMS, and Active Directory dependencies are available.

Run the read-only local matrix with:

```powershell
./tests/Integration/Invoke-IntegrationMatrix.ps1
```

Add a remote computer and explicit credentials with:

```powershell
./tests/Integration/Invoke-IntegrationMatrix.ps1 `
    -RemoteComputer WS01 `
    -Credential (Get-Credential)
```

Add KMS-host and Active Directory read paths with:

```powershell
./tests/Integration/Invoke-IntegrationMatrix.ps1 `
    -KmsHost KMS01 `
    -DirectoryServer dc01.example.test `
    -DirectoryCredential (Get-Credential)
```

Destructive tests are excluded unless `-AllowMutation` is supplied. The current destructive KMS-host probe writes the host's existing activation interval back to the same value and verifies the provider read-back result. It still invokes a real mutating SPP method and therefore must only be used in an isolated validation environment.

```powershell
./tests/Integration/Invoke-IntegrationMatrix.ps1 `
    -KmsHost KMS01 `
    -Credential (Get-Credential) `
    -AllowMutation
```

Credentials are passed as in-process `PSCredential` objects. The harness does not serialize them to environment variables or fixture files. Product keys, confirmation IDs, and token PINs are not accepted by this harness.

The machine-readable scenario inventory is in `IntegrationMatrix.psd1`. It currently covers local DCOM reporting, token provider access, remote WinRM with current or explicit identity, KMS-host reporting, Active Directory activation-object enumeration, and an opt-in KMS-host mutation/read-back path.
