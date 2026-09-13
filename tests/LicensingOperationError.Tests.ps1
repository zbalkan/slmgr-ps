BeforeAll {
    . $PSScriptRoot/../src/Private/New-LicensingOperationResult.ps1
    . $PSScriptRoot/../src/Private/New-LicensingOperationError.ps1
    . $PSScriptRoot/../src/Private/Complete-LicensingOperationBatch.ps1
}

Describe 'New-LicensingOperationError' {
    It 'maps provider error metadata into the failed result and structured error' {
        $providerException = [System.InvalidOperationException]::new('Activation failed')
        $providerException.Data['ErrorCode'] = '0xC004F050'
        $providerError = [System.Management.Automation.ErrorRecord]::new(
            $providerException,
            'SppProviderMethodFailed',
            [System.Management.Automation.ErrorCategory]::InvalidResult,
            'Activate')

        $structured = New-LicensingOperationError `
            -ErrorRecord $providerError `
            -ComputerName WS01 `
            -Operation Activate `
            -ActivationId ([Guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee') `
            -ProductName Windows

        $structured.Result.Success | Should -BeFalse
        $structured.Result.ComputerName | Should -Be 'WS01'
        $structured.Result.Operation | Should -Be 'Activate'
        $structured.Result.ErrorCode | Should -Be '0xC004F050'
        $structured.Result.ErrorMessage | Should -Be 'Activation failed'
        $structured.Result.VerificationState | Should -Be 'Failed'
        $structured.ErrorRecord.FullyQualifiedErrorId | Should -Match '^LicensingOperationFailed'
        $structured.ErrorRecord.TargetObject | Should -Be $structured.Result
        $structured.ErrorRecord.Exception.InnerException | Should -Be $providerException
    }

    It 'does not mislabel a generic exception HRESULT as a licensing error code' {
        $exception = [System.InvalidOperationException]::new('Generic failure')
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'GenericFailure',
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $null)

        $structured = New-LicensingOperationError `
            -ErrorRecord $errorRecord -ComputerName localhost -Operation Test

        $structured.Result.ErrorCode | Should -BeNullOrEmpty
    }
}

Describe 'Complete-LicensingOperationBatch' {
    It 'does nothing when there are no failures' {
        $failures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        { Complete-LicensingOperationBatch -Failures $failures } | Should -Not -Throw
    }

    It 'throws one distinct aggregate error containing all failed results' {
        $failures = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        foreach ($computer in 'WS01', 'WS02')
        {
            $source = [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new("Failure on $computer"),
                'SourceFailure',
                [System.Management.Automation.ErrorCategory]::InvalidOperation,
                $computer)
            $structured = New-LicensingOperationError `
                -ErrorRecord $source -ComputerName $computer -Operation Activate
            $failures.Add($structured.ErrorRecord)
        }

        $caught = $null
        try
        {
            Complete-LicensingOperationBatch -Failures $failures
        }
        catch
        {
            $caught = $_
        }

        $caught | Should -Not -BeNullOrEmpty
        $caught.FullyQualifiedErrorId | Should -Match '^LicensingBatchFailed'
        @($caught.TargetObject).Count | Should -Be 2
        @($caught.Exception.Data['Failures']).Count | Should -Be 2
        $caught.Exception.InnerExceptions.Count | Should -Be 2
        @($caught.TargetObject).ComputerName | Should -Be @('WS01', 'WS02')
    }
}
