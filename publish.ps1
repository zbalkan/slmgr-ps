#Requires -RunAsAdministrator
#Requires -Version 5

$apiKey = Get-Content -Path.\.apikey -Raw
$module = 'slmgr-ps'

Publish-Module -Name $module -NuGetApiKey $apiKey
