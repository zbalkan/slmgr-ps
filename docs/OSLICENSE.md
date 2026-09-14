# Relationship to Microsoft's OSLicense Module

See [README.md](../README.md) for installation and usage.

Microsoft's `OSLicense` module is the official Microsoft PowerShell surface for supported Windows licensing administration. `slmgr-ps` is not an adapter for it and does not use it as a runtime dependency or fallback.

| Concern                            | `slmgr-ps`                                                           | `OSLicense`                                                                      |
| ---------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Ownership and support              | Independent community project                                        | Microsoft-provided module                                                        |
| Implementation relationship        | Uses documented SPP CIM and other public Windows interfaces directly | Microsoft implementation                                                         |
| Runtime dependency between the two | None                                                                 | None required by `slmgr-ps`                                                      |
| `slmgr.vbs` parity documentation   | Explicitly maintained in [docs/slmgr-comparison.md](slmgr-comparison.md) | Not used as the compatibility contract for this project                       |
| Project contract                   | PowerShell-native 1.x commands documented here                       | Defined by Microsoft's module documentation for the installed Windows generation |

This table is intentionally architectural rather than a cmdlet-by-cmdlet equivalence claim. `OSLicense` can evolve with Windows, and its presence or absence does not change how `slmgr-ps` executes. New deployments should generally prefer OSLicense where it is available and meets their requirements. `slmgr-ps` remains useful for existing automation, its documented remote and batch workflows, Windows Script Host-free environments, and deployment contexts where OSLicense is unavailable.
