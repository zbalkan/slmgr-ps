BeforeAll {
    $script:Contract = Import-PowerShellDataFile $PSScriptRoot/PublicContract.psd1
    Import-Module $PSScriptRoot/../src/slmgr-ps.psd1 -Force
}

Describe 'Public command contract stability' {
    It 'exports exactly the functions declared by the 1.x contract' {
        $module = Get-Module slmgr-ps
        $actual = @($module.ExportedFunctions.Keys | Sort-Object)
        $expected = @($script:Contract.Functions.Keys | Sort-Object)

        Compare-Object $actual $expected | Should -BeNullOrEmpty
    }

    It 'preserves established public parameter names' {
        foreach ($entry in $script:Contract.Functions.GetEnumerator())
        {
            $command = Get-Command $entry.Key -Module slmgr-ps -ErrorAction Stop
            foreach ($parameterName in $entry.Value.Parameters)
            {
                $command.Parameters.Keys | Should -Contain $parameterName
            }
        }
    }

    It 'preserves established parameter aliases' {
        foreach ($entry in $script:Contract.Functions.GetEnumerator())
        {
            if (-not $entry.Value.ContainsKey('ParameterAliases')) { continue }

            $command = Get-Command $entry.Key -Module slmgr-ps -ErrorAction Stop
            foreach ($parameterEntry in $entry.Value.ParameterAliases.GetEnumerator())
            {
                $parameter = $command.Parameters[$parameterEntry.Key]
                foreach ($alias in $parameterEntry.Value)
                {
                    @($parameter.Aliases) | Should -Contain $alias
                }
            }
        }
    }

    It 'preserves ShouldProcess on mutating commands' {
        foreach ($entry in $script:Contract.Functions.GetEnumerator())
        {
            if (-not $entry.Value.ContainsKey('SupportsShouldProcess')) { continue }

            $command = Get-Command $entry.Key -Module slmgr-ps -ErrorAction Stop
            $metadata = [System.Management.Automation.CommandMetadata]::new($command)
            $metadata.SupportsShouldProcess | Should -Be $entry.Value.SupportsShouldProcess
        }
    }

    It 'preserves the exported alias and cmdlet surface' {
        $module = Get-Module slmgr-ps
        $actualAliases = @($module.ExportedAliases.Keys | Sort-Object)
        $expectedAliases = @($script:Contract.ExportedAliases | Sort-Object)
        $actualCmdlets = @($module.ExportedCmdlets.Keys | Sort-Object)
        $expectedCmdlets = @($script:Contract.ExportedCmdlets | Sort-Object)

        Compare-Object $actualAliases $expectedAliases | Should -BeNullOrEmpty
        Compare-Object $actualCmdlets $expectedCmdlets | Should -BeNullOrEmpty
    }
}
