BeforeAll {
    . $PSScriptRoot/../src/Private/Get-SystemLicenseFile.ps1
}

Describe 'Get-SystemLicenseFile' {
    It 'returns license files from OEM and SPP token directories in deterministic order' {
        $oemPath = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'System32\oem') -Force
        $tokenPath = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'System32\spp\tokens\nested') -Force
        [System.IO.File]::WriteAllText((Join-Path $oemPath.FullName 'z.xrm-ms'), 'z')
        [System.IO.File]::WriteAllText((Join-Path $tokenPath.FullName 'a.xrm-ms'), 'a')
        [System.IO.File]::WriteAllText((Join-Path $tokenPath.FullName 'ignored.xml'), 'ignored')

        $result = @(Get-SystemLicenseFile -SystemRoot $TestDrive)

        $result.Count | Should -Be 2
        $result[0].Name | Should -Be 'z.xrm-ms'
        $result[1].Name | Should -Be 'a.xrm-ms'
        $result.Name | Should -Not -Contain 'ignored.xml'
    }

    It 'ignores a missing candidate directory when the other contains licenses' {
        $tokenPath = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'System32\spp\tokens') -Force
        [System.IO.File]::WriteAllText((Join-Path $tokenPath.FullName 'license.xrm-ms'), 'license')

        @(Get-SystemLicenseFile -SystemRoot $TestDrive).Count | Should -Be 1
    }

    It 'throws when no system license files are found' {
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'System32\oem') -Force | Out-Null

        { Get-SystemLicenseFile -SystemRoot $TestDrive } |
            Should -Throw -ExpectedMessage '*No system license files were found*'
    }

    It 'rejects an unavailable system root' {
        { Get-SystemLicenseFile -SystemRoot '' } | Should -Throw
    }
}
