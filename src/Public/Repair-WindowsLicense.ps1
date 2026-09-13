#Requires -Version 5

<#
.SYNOPSIS
Reinstalls known-good Windows system license files.
.DESCRIPTION
Finds .xrm-ms files below the local Windows OEM and SPP token directories and
reinstalls them through SoftwareLicensingService. This operation is local-only
because the files must come from the target system's own Windows installation.
.INPUTS
None.
.OUTPUTS
slmgr-ps.LicensingOperationResult. Emits one result for localhost when the operation
is attempted. Throws one aggregate error after attempting every discovered license
file when one or more files fail.
.EXAMPLE
Repair-WindowsLicense -Verbose
.LINK
https://github.com/zbalkan/slmgr-ps
#>
function Repair-WindowsLicense
{
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High')]
    param()

    $licenseFiles = @(Get-SystemLicenseFile -ErrorAction Stop)
    if (-not $PSCmdlet.ShouldProcess(
            'localhost',
            "Reinstall $($licenseFiles.Count) Windows system license file(s)"))
    {
        return
    }

    $repairFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
    $fileFailures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
    $session = $null
    try
    {
        $session = Get-Session -Computer 'localhost' -Credentials $null -ErrorAction Stop
        $service = Get-CimInstance -CimSession $session -ClassName SoftwareLicensingService -ErrorAction Stop
        $installedAny = $false

        foreach ($file in $licenseFiles)
        {
            try
            {
                $license = @(Get-LicenseFileContent -Path $file.FullName -ErrorAction Stop)[0]
                $service | Invoke-SppCimMethod -MethodName InstallLicense -Arguments @{ License = $license.Content }
                $installedAny = $true
            }
            catch
            {
                $message = "Failed to reinstall system license file '$($file.FullName)': $($_.Exception.Message)"
                $exception = [System.InvalidOperationException]::new($message, $_.Exception)
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $exception,
                    'WindowsSystemLicenseRepairFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $file.FullName)
                $fileFailures.Add($errorRecord)
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
                $message = "System licenses were reinstalled, but licensing status could not be refreshed: $($_.Exception.Message)"
                $exception = [System.InvalidOperationException]::new($message, $_.Exception)
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $exception,
                    'WindowsSystemLicenseRefreshFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    'localhost')
                $fileFailures.Add($errorRecord)
            }
        }
    }
    catch
    {
        $message = "System license repair could not start: $($_.Exception.Message)"
        $exception = [System.InvalidOperationException]::new($message, $_.Exception)
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'WindowsSystemLicenseRepairStartFailed',
            [System.Management.Automation.ErrorCategory]::ConnectionError,
            'localhost')
        $fileFailures.Add($errorRecord)
    }
    finally
    {
        if ($null -ne $session)
        {
            Remove-CimSession -CimSession $session -ErrorAction Ignore | Out-Null
        }
    }

    if ($fileFailures.Count -eq 0)
    {
        New-LicensingOperationResult `
            -ComputerName localhost `
            -Operation RepairSystemLicenses `
            -Success $true `
            -VerificationState ProviderAccepted
    }
    else
    {
        $innerExceptions = [System.Collections.Generic.List[System.Exception]]::new()
        foreach ($failure in $fileFailures) { $innerExceptions.Add($failure.Exception) }
        $targetException = [System.AggregateException]::new(
            "$($fileFailures.Count) system license repair failure(s). First failure: $($fileFailures[0].Exception.Message)",
            $innerExceptions.ToArray())
        $targetException.Data['Failures'] = $fileFailures.ToArray()
        $targetError = [System.Management.Automation.ErrorRecord]::new(
            $targetException,
            'WindowsSystemLicenseRepairFailed',
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            'localhost')
        $structured = New-LicensingOperationError `
            -ErrorRecord $targetError `
            -ComputerName localhost `
            -Operation RepairSystemLicenses
        $repairFailures.Add($structured.ErrorRecord)
        Write-Output $structured.Result
    }

    Complete-LicensingOperationBatch -Failures $repairFailures
}
