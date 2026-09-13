@{
    Scenarios = @(
        @{
            Name = 'LocalSppRead'
            Tags = @('Integration', 'ReadOnly')
            RequiredInputs = @()
            Coverage = @('Local DCOM', 'SPP reporting')
        }
        @{
            Name = 'LocalTokenRead'
            Tags = @('Integration', 'ReadOnly')
            RequiredInputs = @()
            Coverage = @('Token issuance-license provider access')
        }
        @{
            Name = 'RemoteSppRead'
            Tags = @('Integration', 'ReadOnly')
            RequiredInputs = @('RemoteComputer')
            Coverage = @('Remote WinRM', 'SPP reporting')
        }
        @{
            Name = 'RemoteCredentialRead'
            Tags = @('Integration', 'ReadOnly')
            RequiredInputs = @('RemoteComputer', 'Credential')
            Coverage = @('Remote WinRM', 'Explicit PSCredential')
        }
        @{
            Name = 'KmsHostRead'
            Tags = @('Integration', 'ReadOnly')
            RequiredInputs = @('KmsHost')
            Coverage = @('KMS host provider state', 'Request counters', 'Intervals')
        }
        @{
            Name = 'ActiveDirectoryRead'
            Tags = @('Integration', 'ReadOnly')
            RequiredInputs = @('DirectoryServer')
            Coverage = @('ActiveDirectory module', 'Forest connectivity', 'Activation-object enumeration')
        }
        @{
            Name = 'KmsHostMutationVerification'
            Tags = @('Integration', 'Destructive')
            RequiredInputs = @('KmsHost', 'AllowMutation')
            Coverage = @('KMS host mutation', 'Provider read-back verification')
        }
    )
}
