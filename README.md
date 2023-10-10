# slmgr-ps

A drop in replacement for slmgr script

NB: Currently the features are limited to KMS scenarios.

## Usage

```powershell
Install-Module slmgr-ps

Start-WindowsActivation -WhatIf

# Activates the local computer
Start-WindowsActivation -Verbose

# Activates the computer named WS01
Start-WindowsActivation -Computer WS01

# Activates the computer named WS01 against server.domain.net:2500
Start-WindowsActivation -Computer WS01 -KMSServerFQDN server.domain.net -KMSServerPort 2500
```
