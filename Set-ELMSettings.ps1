<#
Required permissions for Application:
- EntitlementManagement.ReadWrite.All

.NOTES
Save Application Secret to xml file
$Password = Get-Credential
$Password | Export-clixml -path .\Secret.xml

.EXAMPLE
Before running the script 
$secret = (Import-CLixml -path .\Secret.xml).GetNetworkCredential().password
.\Set-ELMSettings.ps1 -ApplicationID "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -AccessSecret $secret -TenatDomainName "TENANT.COM"-ExternalUserLifecycleAction BlockSignInAndDelete -DaysUntilExternalUserDeletedAfterBlocked 30
$secret = $null

.EXAMPLE
$secret = (Import-CLixml -path .\Secret.xml).GetNetworkCredential().password
.\Set-ELMSettings.ps1 -ApplicationID "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -AccessSecret $secret -TenatDomainName "TENANT.COM"-ExternalUserLifecycleAction None
$secret = $null

.EXAMPLE
$secret = (Import-CLixml -path .\Secret.xml).GetNetworkCredential().password
.\Set-ELMSettings.ps1 -ApplicationID "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -AccessSecret $secret -TenatDomainName "TENANT.COM" -ExternalUserLifecycleAction BlockSignIn
$secret = $null

#>

[CmdletBinding()]
param (
    [string] $ApplicationID,
    [string] $AccessSecret,
    [string] $TenatDomainName,
    [string] $ExternalUserLifecycleAction,
    [int64] $DaysUntilExternalUserDeletedAfterBlocked

)
Start-Transcript -Path .\Configure-ELMSettings.log

#Region Connection
$Body = @{    
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    client_Id     = $ApplicationID
    Client_Secret = $AccessSecret
} 

$connectGraph = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenatDomainName/oauth2/v2.0/token" -Method POST -Body $Body -ContentType 'application/x-www-form-urlencoded'

$authHeader = @{
    'Authorization' = "Bearer $($connectGraph.access_token)"
}
#endregion

$mainURI = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/"

#region Connected Organisation
Write-Host "Contiguring Entitlement Management Settings..." -ForegroundColor Cyan
$uri = $mainURI + "settings"
$body = @{
    externalUserLifecycleAction              = $ExternalUserLifecycleAction 
    daysUntilExternalUserDeletedAfterBlocked = $DaysUntilExternalUserDeletedAfterBlocked 
}

$body = $body | ConvertTo-Json -Depth 10
Write-Host "Configuring ELM Settings with the following parameters: ExternalUserLifecycleAction '$ExternalUserLifecycleAction' DaysUntilExternalUserDeletedAfterBlocked '$DaysUntilExternalUserDeletedAfterBlocked' " -ForegroundColor Yellow
Invoke-RestMethod -Headers $authHeader -Uri $uri -body $body -Method PAtch -ContentType "application/json"

Write-Host "Script run finished..." -ForegroundColor Cyan
Stop-Transcript
