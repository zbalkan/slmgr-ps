#Requires -Version 5

<#
.SYNOPSIS
Installs one or more Windows license files.
.DESCRIPTION
Reads .xrm-ms license files from the computer running PowerShell and installs their
contents on each target through SoftwareLicensingService. Paths are resolved and read
before any CIM session is opened. The Software Protection Platform performs license
validation at runtime.
.INPUTS
String[]. You can pass computer names through the pipeline.
.OUTPUTS
None if successful. Throws after processing all targets when any operation fails.
.EXAMPLE
Install-WindowsLicense -Path C:\Licenses\example.xrm-ms
.EXAMPLE
Install-WindowsLicense -Computer WS01, WS02 -Credentials (Get-Credential) -Path C:\Licenses\base.xrm-ms
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Install-WindowsLicense
{
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High')]
    param(
        [Parameter(Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [AllowNull()]
        [string[]]$Computer = @('localhost'),

        [Parameter()]
        [AllowNull()]
        [PSCredential]$Credentials,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path
    )

    begin
    {
        $licenses = @(Get-LicenseFileContent -Path $Path -ErrorAction Stop)
        $installFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
    }
    process
    {
        foreach ($targetComputer in $Computer)
        {
            $action = "Install $($licenses.Count) Windows license file(s)"
            if (-not $PSCmdlet.ShouldProcess($targetComputer, $action))
            {
                continue
            }

            $session = $null
            try
            {
                $session = Get-Session -Computer $targetComputer -Credentials $Credentials -ErrorAction Stop
                $service = Get-CimInstance -CimSession $session -ClassName SoftwareLicensingService -ErrorAction Stop
                $installedAny = $false

                foreach ($license in $licenses)
                {
                    try
                    {
                        $service | Invoke-SppCimMethod -MethodName InstallLicense -Arguments @{ License = $license.Content }
                        $installedAny = $true
                    }
                    catch
                    {
                        $message = "Failed to install license file '$($license.Path)' on '$targetComputer': $($_.Exception.Message)"
                        $exception = [System.InvalidOperationException]::new($message, $_.Exception)
                        $target = [PSCustomObject]@{ ComputerName = $targetComputer; Path = $license.Path }
                        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                            $exception,
                            'WindowsLicenseInstallFailed',
                            [System.Management.Automation.ErrorCategory]::InvalidOperation,
                            $target)
                        $installFailures.Add($errorRecord)
                    }
                }

                if ($installedAny)
                {
                    try
                    {
                        $service | Invoke-SppCimMethod -MethodName RefreshLicenseStatus
                    }
                    catch
                    {
                        $message = "License files were installed on '$targetComputer', but licensing status could not be refreshed: $($_.Exception.Message)"
                        $exception = [System.InvalidOperationException]::new($message, $_.Exception)
                        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                            $exception,
                            'WindowsLicenseRefreshFailed',
                            [System.Management.Automation.ErrorCategory]::InvalidOperation,
                            $targetComputer)
                        $installFailures.Add($errorRecord)
                    }
                }
            }
            catch
            {
                $message = "License installation could not start on '$targetComputer': $($_.Exception.Message)"
                $exception = [System.InvalidOperationException]::new($message, $_.Exception)
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $exception,
                    'WindowsLicenseTargetFailed',
                    [System.Management.Automation.ErrorCategory]::ConnectionError,
                    $targetComputer)
                $installFailures.Add($errorRecord)
            }
            finally
            {
                if ($null -ne $session)
                {
                    Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
                }
            }
        }
    }
    end
    {
        if ($installFailures.Count -gt 0)
        {
            foreach ($failure in $installFailures)
            {
                Write-Error -ErrorRecord $failure
            }
            $PSCmdlet.ThrowTerminatingError($installFailures[0])
        }
    }
}
