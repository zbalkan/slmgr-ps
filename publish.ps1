#Requires -RunAsAdministrator
#Requires -Version 5

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$apiKey = Get-Content -Path.\.apikey -Raw
$module = '.\slmgr-ps.psd1'

Publish-Module -Name $module -NuGetApiKey $apiKey
