BeforeAll {
    . $PSScriptRoot/../src/Private/Resolve-KmsEndpoint.ps1
}

Describe 'Resolve-KmsEndpoint' {
    It 'accepts a single-label host name and applies the default port' {
        $result = Resolve-KmsEndpoint -Endpoint 'kms01'
        $result.Host | Should -Be 'kms01'
        $result.Port | Should -Be 1688
    }

    It 'accepts an FQDN with an explicit port parameter' {
        $result = Resolve-KmsEndpoint -Endpoint 'kms.example.test' -Port 2500
        $result.Host | Should -Be 'kms.example.test'
        $result.Port | Should -Be 2500
    }

    It 'extracts a port from a DNS endpoint' {
        $result = Resolve-KmsEndpoint -Endpoint 'kms.example.test:2500'
        $result.Host | Should -Be 'kms.example.test'
        $result.Port | Should -Be 2500
    }

    It 'accepts a valid IPv4 endpoint' {
        $result = Resolve-KmsEndpoint -Endpoint '192.0.2.10:1689'
        $result.Host | Should -Be '192.0.2.10'
        $result.Port | Should -Be 1689
    }

    It 'accepts bracketed IPv6 and removes the brackets from the provider value' {
        $result = Resolve-KmsEndpoint -Endpoint '[2001:db8::10]:1689'
        $result.Host | Should -Be '2001:db8::10'
        $result.Port | Should -Be 1689
    }

    It 'rejects an unbracketed IPv6 address' {
        { Resolve-KmsEndpoint -Endpoint '2001:db8::10' } |
            Should -Throw -ExpectedMessage '*must be enclosed in brackets*'
    }

    It 'rejects an invalid IPv4-shaped address' {
        { Resolve-KmsEndpoint -Endpoint '999.0.2.10' } |
            Should -Throw -ExpectedMessage '*Invalid IPv4*'
    }

    It 'rejects an incomplete numeric address instead of treating it as DNS' {
        { Resolve-KmsEndpoint -Endpoint '192.0.2' } |
            Should -Throw -ExpectedMessage '*Invalid IPv4*'
    }

    It 'rejects duplicate port specifications' {
        { Resolve-KmsEndpoint -Endpoint 'kms01:1688' -Port 2500 } |
            Should -Throw -ExpectedMessage '*either in Endpoint or with Port*'
    }

    It 'rejects an out-of-range embedded port' {
        { Resolve-KmsEndpoint -Endpoint 'kms01:65536' } |
            Should -Throw -ExpectedMessage '*Invalid KMS server port*'
    }

    It 'rejects malformed host labels' {
        { Resolve-KmsEndpoint -Endpoint '-kms01.example.test' } |
            Should -Throw -ExpectedMessage '*Invalid KMS server host name*'
    }
}

Describe 'Resolve-KmsLookupDomain' {
    It 'accepts an FQDN' {
        Resolve-KmsLookupDomain -LookupDomain 'activation.example.test' |
            Should -Be 'activation.example.test'
    }

    It 'rejects a single-label DNS name' {
        { Resolve-KmsLookupDomain -LookupDomain 'activation' } |
            Should -Throw -ExpectedMessage '*Invalid KMS lookup domain*'
    }

    It 'rejects an IP address' {
        { Resolve-KmsLookupDomain -LookupDomain '192.0.2.10' } |
            Should -Throw -ExpectedMessage '*Invalid KMS lookup domain*'
    }
}
