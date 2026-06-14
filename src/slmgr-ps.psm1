#Get public and private function definition files.
$Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1  -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

#Dot source the files - Private first so enums and helpers are available when Public files load
Foreach ($import in @($Private + $Public))
{
    Try
    {
        . $import.fullname
    }
    Catch
    {
        throw "Failed to import function $($import.fullname): $_"
    }
}

Export-ModuleMember -Function $Public.Basename
