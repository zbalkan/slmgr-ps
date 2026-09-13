BeforeAll {
    . $PSScriptRoot/../src/Private/Get-LicenseFileContent.ps1
}

Describe 'Get-LicenseFileContent' {
    It 'returns the canonical path and complete content' {
        $licensePath = Join-Path $TestDrive 'license.xrm-ms'
        [System.IO.File]::WriteAllText($licensePath, "<license>`n  value`n</license>")

        $result = Get-LicenseFileContent -Path $licensePath

        $result.Path | Should -Be (Get-Item $licensePath).FullName
        $result.Content | Should -Be "<license>`n  value`n</license>"
    }

    It 'preserves input order for multiple files' {
        $firstPath = Join-Path $TestDrive 'first.xrm-ms'
        $secondPath = Join-Path $TestDrive 'second.xrm-ms'
        [System.IO.File]::WriteAllText($firstPath, 'first')
        [System.IO.File]::WriteAllText($secondPath, 'second')

        $result = @(Get-LicenseFileContent -Path $secondPath, $firstPath)

        $result.Count | Should -Be 2
        $result[0].Content | Should -Be 'second'
        $result[1].Content | Should -Be 'first'
    }

    It 'rejects a missing file' {
        { Get-LicenseFileContent -Path (Join-Path $TestDrive 'missing.xrm-ms') } |
            Should -Throw
    }

    It 'rejects a directory' {
        $directory = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'directory.xrm-ms')

        { Get-LicenseFileContent -Path $directory.FullName } |
            Should -Throw -ExpectedMessage '*is a directory*'
    }

    It 'rejects a file without the xrm-ms extension' {
        $licensePath = Join-Path $TestDrive 'license.xml'
        [System.IO.File]::WriteAllText($licensePath, '<license />')

        { Get-LicenseFileContent -Path $licensePath } |
            Should -Throw -ExpectedMessage '*must use the .xrm-ms extension*'
    }

    It 'rejects an empty file' {
        $licensePath = Join-Path $TestDrive 'empty.xrm-ms'
        [System.IO.File]::WriteAllText($licensePath, '')

        { Get-LicenseFileContent -Path $licensePath } |
            Should -Throw -ExpectedMessage '*is empty*'
    }

    It 'rejects duplicate canonical paths' {
        $licensePath = Join-Path $TestDrive 'duplicate.xrm-ms'
        [System.IO.File]::WriteAllText($licensePath, '<license />')

        { Get-LicenseFileContent -Path $licensePath, $licensePath } |
            Should -Throw -ExpectedMessage '*specified more than once*'
    }
}
