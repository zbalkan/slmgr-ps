function Get-LicenseFileContent
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path
    )

    $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($inputPath in $Path)
    {
        if ([string]::IsNullOrWhiteSpace($inputPath))
        {
            throw 'License file paths cannot be empty.'
        }

        $resolvedPath = Resolve-Path -LiteralPath $inputPath -ErrorAction Stop
        if ($resolvedPath.Provider.Name -ne 'FileSystem')
        {
            throw "License file '$inputPath' must use the FileSystem provider."
        }

        $file = Get-Item -LiteralPath $resolvedPath.ProviderPath -Force -ErrorAction Stop
        if ($file.PSIsContainer)
        {
            throw "License file '$inputPath' is a directory."
        }
        if ($file.Extension -ine '.xrm-ms')
        {
            throw "License file '$inputPath' must use the .xrm-ms extension."
        }
        if (-not $seenPaths.Add($file.FullName))
        {
            throw "License file '$($file.FullName)' was specified more than once."
        }

        try
        {
            $content = [System.IO.File]::ReadAllText($file.FullName)
        }
        catch
        {
            throw "License file '$($file.FullName)' could not be read: $($_.Exception.Message)"
        }
        if ([string]::IsNullOrWhiteSpace($content))
        {
            throw "License file '$($file.FullName)' is empty."
        }

        [PSCustomObject]@{
            Path    = $file.FullName
            Content = $content
        }
    }
}
