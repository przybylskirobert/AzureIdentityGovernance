<#
.NOTES
Required permissions for Application:
Policy.Read.All
Policy.ReadWrite.ConditionalAccess
Application.Read.All

Save Application Secret to xml file
$Password = Get-Credential
$Password | Export-clixml -path .\Secret.xml

.EXAMPLE
Before running the script 
$secret = (Import-CLixml -path .\Secret.xml).GetNetworkCredential().password
.\New-CaToUPolicy.ps1 -ApplicationID "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -AccessSecret $secret -TenatDomainName "TENANT.COM" -TermsOfUseName "TERMS_OF_USE_NAME" -ExcludeUser 'USER@TENANT.COM'
$secret = $null
#>

param (
    [Parameter(mandatory=$true)]
    [string] $ApplicationID,
    [Parameter(mandatory=$true)]
    [string] $AccessSecret,
    [Parameter(mandatory=$true)]
    [string] $TenatDomainName,
    [string] $Uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
    [Parameter(mandatory=$true)]
    [string] $TermsOfUseName,
    [Parameter(mandatory=$true)]
    [string] $ExcludeUser
)

Start-Transcript -Path .\New-CaToUPolicy.log
Write-Host "Logging to Azure AD" -ForegroundColor Cyan
Connect-AzureAD | out-null

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

#region  Configure CA Policy for Terms of Use 

$displayName = "External Users and Guests - $TermsOfUseName"
$policyChecker = (Invoke-RestMethod -Uri $Uri -Headers $authHeader -Method get).value | Where-Object { $_.DisplayName -eq $displayName }
if ($null -eq $policyChecker) {
    $touUri = "https://graph.microsoft.com/beta/identityGovernance/termsOfUse/agreements"
    $termsOfUseId = ((Invoke-RestMethod -Headers $authHeader -Uri $touUri -Method get).value | Where-Object { $_.displayName -eq $TermsOfUseName }).id

    $excludedUserId = (Get-AzureADUser -SearchString $ExcludeUser).ObjectId

    $body = @{
        displayName   = $displayName 
        state         = "enabled" 
        grantControls = @{
            builtInControls = @('mfa')
            operator        = "AND"
            termsOfUse      = @($termsOfUseId)
        }
        conditions    = @{
            applications   = @{
                includeApplications = @("All")
            }
            clientAppTypes = @("all")
            users          = @{
                includeUsers = @('GuestsOrExternalUsers')
                excludeUsers = @($excludedUserId)
            }
        }
    }

    $body = $body | ConvertTo-Json -Depth 10
    Write-Host "Adding new Conditional Access Policy '$displayName' that will require MFA and Tou for External and Guest users" -ForegroundColor Yellow
    Invoke-RestMethod -Headers $authHeader -Uri $uri -body $body -Method Post -ContentType "application/json"
} else {
    Write-Host "Conditional Access Policy '$displayName' already exists" -ForegroundColor Yellow
}

#endregion

Write-Host "Script run finished..." -ForegroundColor Cyan
Stop-Transcript