<#
.NOTES
Required permissions for Application:
Agreement.ReadWrite.All

Save Application Secret to xml file
$Password = Get-Credential
$Password | Export-clixml -path .\Secret.xml

.EXAMPLE
Before running the script 
$secret = (Import-CLixml -path .\Secret.xml).GetNetworkCredential().password
.\New-TermsOfUse.ps1 -ApplicationID "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -AccessSecret $secret -TenatDomainName "TENANT.COM" -ViewingBeforeAcceptanceRequired -DefaultToU -TermsOfUseName "TERMS_OF_USE_NAME" -LanguageCode 'en' -ReacceptRequiredFrequencyDays NUMBER_OF_DAYS
$secret = $null

#>

param (
    [string] $ApplicationID,
    [string] $AccessSecret,
    [string] $TenatDomainName,
    [string] $Uri = "https://graph.microsoft.com/beta/identityGovernance/termsOfUse/agreements",
    [string] $TermsOfUseName,
    [Switch] $DefaultToU,
    [Switch] $ViewingBeforeAcceptanceRequired,
    [string] $LanguageCode,
    [string] $ReacceptRequiredFrequencyDays,
    [switch] $PerDeviceAcceptanceRequired
)

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

$terms = Invoke-RestMethod -Headers $authHeader -Uri $Uri -Method Get

if ($DefaultToU) {
    $isDefault = $true
}
else {
    $isDefault = $false
}

if ($ViewingBeforeAcceptanceRequired) {
    $isViewingBeforeAcceptanceRequired = $true
}
else {
    $isViewingBeforeAcceptanceRequired = $false
}

if ($PerDeviceAcceptanceRequired) {
    $isPerDeviceAcceptanceRequired = $true
}
else {
    $isPerDeviceAcceptanceRequired = $false
}

$userReacceptRequiredFrequency = "P" + $ReacceptRequiredFrequencyDays + "D"

$output = @(
    $(New-Object PSObject -Property @{
            displayName                       = $TermsOfUseName; 
            isViewingBeforeAcceptanceRequired = $isViewingBeforeAcceptanceRequired ; 
            userReacceptRequiredFrequency     = $userReacceptRequiredFrequency; 
            isPerDeviceAcceptanceRequired     = $isPerDeviceAcceptanceRequired; 
            fileName                          = "RemoveMeAndUploadNewFile.pdf"; 
            language                          = $language; 
            isDefault                         = $isDefault
        }
    )
)


if ($null -eq ($terms.value | where-object { $_.displayname -eq "$TermsOfUseName" })) {
    $body = @{
        displayName                       = $TermsOfUseName 
        isViewingBeforeAcceptanceRequired = $isViewingBeforeAcceptanceRequired 
        userReacceptRequiredFrequency     = $userReacceptRequiredFrequency
        isPerDeviceAcceptanceRequired     = $isPerDeviceAcceptanceRequired
        files                             = @(
            @{
                fileName  = "RemoveMeAndUploadNewFile.pdf"
                language  = $LanguageCode
                isDefault = $isDefault
                fileData  = @{
                    data = "XXXXXXXXXXXXXXX="
                }
            }
        )
    }

    $body = $body | ConvertTo-Json -Depth 10
    Write-Host "Adding new Terms of Use '$TermsOfUseName' with the following parameters" -ForegroundColor Yellow
    $output
    Write-Host "Please remember to upload new ToU file https://portal.azure.com/#blade/Microsoft_AAD_ERM/DashboardBlade/termsOfUse"
    Invoke-RestMethod -Headers $authHeader -Uri $uri -body $body -Method Post -ContentType "application/json"
}
else {
    Write-Host "Terms of Use: '$TermsOfUseName' already exist" -ForegroundColor Green
}
