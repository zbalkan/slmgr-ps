function Get-SystemLicenseFile
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$SystemRoot = $env:SystemRoot
    )

    if ([string]::IsNullOrWhiteSpace($SystemRoot))
    {
        throw 'SystemRoot is unavailable; system license files cannot be located.'
    }

    $candidateRoots = @(
        (Join-Path $SystemRoot 'System32\oem')
        (Join-Path $SystemRoot 'System32\spp\tokens')
    )
    $directories = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    foreach ($candidateRoot in $candidateRoots)
    {
        if (Test-Path -LiteralPath $candidateRoot -PathType Container)
        {
            $directory = Get-Item -LiteralPath $candidateRoot -Force -ErrorAction Stop
            if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0)
            {
                $directories.Push($directory)
            }
        }
    }

    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    while ($directories.Count -gt 0)
    {
        $directory = $directories.Pop()
        $children = Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop
        foreach ($child in $children)
        {
            $isReparsePoint = ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            if ($isReparsePoint) { continue }

            if ($child.PSIsContainer)
            {
                $directories.Push($child)
            }
            elseif ($child.Extension -ieq '.xrm-ms' -and $seenPaths.Add($child.FullName))
            {
                $files.Add($child)
            }
        }
    }

    if ($files.Count -eq 0)
    {
        throw "No system license files were found under '$SystemRoot'."
    }

    return @($files | Sort-Object FullName)
}
