<#
Required permissions for Application:
- EntitlementManagement.ReadWrite.All
- Group.ReadWrite.All
- User.ReadWrite.All
- Resource owner righst (Group owner for Application)

.NOTES
There is no solution for RBAC yet.
It has to be done manually.

Save Application Secret to xml file
$Password = Get-Credential
$Password | Export-clixml -path .\Secret.xml

.EXAMPLE
Before running the script 
$secret = (Import-CLixml -path .\Secret.xml).GetNetworkCredential().password
.\New-ELMDeployment.ps1 -ApplicationID "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -AccessSecret $secret -TenatDomainName "TENANT.COM" -ConnectedOrganisationDomainName 'DOMAIN.NAME.COM' -ConnectedOrganisationDisplayName 'DIRECTORY NAME' -InternalSponsorUPN "USER@TENANT.COM" -CatalogName "CATALOG_NAME" -ResourceName "GROUP_TO_SHARE_NAME" -ExternalPolicyName "External_Access_Policy" -InternalPolicyName "Internal_Access_Policy" -BackupApproverUPN 'USER@TENANT.COM'
$secret = $null

#>

[CmdletBinding()]
param (
    [Parameter(mandatory=$true)]
    [string]$ApplicationID,
    [Parameter(mandatory=$true)]
    [string]$AccessSecret,
    [Parameter(mandatory=$true)]
    [string]$TenatDomainName,
    [Parameter(mandatory=$true)]
    [string]$ConnectedOrganisationDomainName,
    [Parameter(mandatory=$true)]
    [string]$ConnectedOrganisationDisplayName,
    [Parameter(mandatory=$true)]
    [string]$InternalSponsorUPN,
    [Parameter(mandatory=$true)]
    [string]$CatalogName,
    [string]$CatalogDescription = "",
    [Parameter(mandatory=$true)]
    [string]$ResourceName,
    [string]$PackageName = "",
    [Parameter(mandatory=$true)]
    [string]$ExternalPolicyName,
    [Parameter(mandatory=$true)]
    [string]$InternalPolicyName,
    [Parameter(mandatory=$true)]
    [string]$BackupApproverUPN
)
Start-Transcript -Path .\New-ELMDeployment.log
Write-Host "Logging to Azure AD" -ForegroundColor Cyan
Connect-AzureAD | out-null # To do: change into the Service Principal

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

if ("" -eq $CatalogDescription) {
    $CatalogDescription = $CatalogName + "_Catalog"
}

if ("" -eq $PackageName) {
    $packageName = ($CatalogName + "_Catalog_" + $ResourceName).replace(" ", "_")
}

$output = @(
    $(New-Object PSObject -Property @{
            ApplicationID                    = $ApplicationID; 
            TenatDomainName                  = $TenatDomainName ; 
            ConnectedOrganisationDomainName  = $ConnectedOrganisationDomainName; 
            ConnectedOrganisationDisplayName = $ConnectedOrganisationDisplayName; 
            InternalSponsorUPN               = $InternalSponsorUPN; 
            CatalogName                      = $CatalogName; 
            CatalogDescription               = $CatalogDescription; 
            ResourceName                     = $ResourceName; 
            PackageName                      = $PackageName; 
            ExternalPolicyName               = $ExternalPolicyName; 
            InternalPolicyName               = $InternalPolicyName; 
            BackupApproverUPN                = $BackupApproverUPN; 
        }
    )
)

#region Connected Organisation
Write-Host "Working on Connected Organisations...." -ForegroundColor Cyan
$uri = $mainURI + "connectedOrganizations"
$connectedOrgs = Invoke-RestMethod -Headers $authHeader -Uri $uri -Method Get

if ($null -eq ($connectedOrgs.value | where-object { $_.displayname -eq "$ConnectedOrganisationDisplayName" })) {
    $body = @{
        displayName     = $ConnectedOrganisationDisplayName 
        description     = $ConnectedOrganisationDisplayName 
        identitySources = @(
            @{
                '@odata.type' = '#microsoft.graph.domainIdentitySource'
                domainName    = $ConnectedOrganisationDomainName
                displayName   = $ConnectedOrganisationDomainName
            }
        )
        state           = 'configured'
    }

    $body = $body | ConvertTo-Json -Depth 10
    Write-Host "Adding new Connected Organisation '$ConnectedOrganisationDisplayName' with domain '$ConnectedOrganisationDomainName'" -ForegroundColor Yellow
    Invoke-RestMethod -Headers $authHeader -Uri $uri -body $body -Method Post -ContentType "application/json"

}
else {
    Write-Host "Connected Organisation '$ConnectedOrganisationDisplayName' with domain '$ConnectedOrganisationDomainName' already exists" -ForegroundColor Green
}
$conenctedOrganisationID = ((Invoke-RestMethod -Headers $authHeader -Uri $uri -Method Get).value | where-Object { $_.displayName -eq $ConnectedOrganisationDisplayName }).id

#endregion

#region Internal Sponsor
Write-Host "Working on Internal Sponsors...." -ForegroundColor Cyan

$userID = (get-azureaduser -SearchString $InternalSponsorUPN).objectId
$uri = $mainURI + "connectedOrganizations/$conenctedOrganisationID/internalSponsors/"
$InternalSponsorUPNs = Invoke-RestMethod -Headers $authHeader -Uri $uri -Method get

if ($null -eq ($InternalSponsorUPNs.value | where-object { $_.id -eq "$userID" })) {
    $uriRef = $uri + '$ref'
    $body = @{
        "@odata.id" = "https://graph.microsoft.com/beta/users/$userId" 
    }
    $body = $body | ConvertTo-Json -Depth 10

    Write-Host "Adding new InternalSponsor '$InternalSponsorUPN' to Connected Organisation '$ConnectedOrganisationDisplayName'" -ForegroundColor Yellow
    Invoke-RestMethod -Headers $authHeader -Uri $uriRef -body $body -Method Post -ContentType "application/json"
}
else {
    Write-Host "Sponsor '$InternalSponsorUPN' already added to organisation '$ConnectedOrganisationDisplayName'" -ForegroundColor Green
}
#endregion

#region Catalog
Write-Host "Working on Catalog...." -ForegroundColor Cyan

$uri = $mainURI + "accessPackageCatalogs"
$catalogs = Invoke-RestMethod -Headers $authHeader -Uri $uri -Method Get

if ($null -eq ($catalogs.value | where-object { $_.displayName -eq "$CatalogName" })) {
    $body = @{
        displayName         = $CatalogName
        description         = $CatalogDescription
        isExternallyVisible = $true
    }
    $body = $body | ConvertTo-Json -Depth 10
    Write-Host "Creating new catalog '$CatalogName' " -ForegroundColor Yellow
    Invoke-RestMethod -Headers $authHeader -body $body -Uri $uri -Method Post -ContentType "application/json"
}
else {
    Write-Host "Catalog '$CatalogName' already exists" -ForegroundColor Green
}
$catalogID = ((Invoke-RestMethod -Headers $authHeader -Uri $uri -Method Get).value | where-Object { $_.displayname -eq $CatalogName }).id
#endregion

#Region Catalog Resources
Write-Host "Working on Catalog Resources...." -ForegroundColor Cyan

$uri = $mainURI + "accessPackageResourceRequests"
$uriChecker = $mainURI + "accessPackageCatalogs/$catalogId/accessPackageResources"
$resourceChecher = (Invoke-RestMethod -Headers $authHeader -Uri $uriChecker -Method Get).value | Where-Object { $_.displayName -eq $ResourceName }
if ($null -eq $resourceChecher) {
    $groupID = (Get-AzureADGroup -SearchString $ResourceName).ObjectID
    $body = @{
        catalogId             = $CatalogId
        requestType           = "AdminAdd"
        justification         = "Automated resource add"
        accessPackageResource = @{
            displayName  = $ResourceName
            originSystem = "AadGroup"
            originId     = $groupID
            description  = $ResourceName
        }
    }
    $body = $body | ConvertTo-Json -Depth 10
    Write-Host "Adding resource with id '$groupId' to catalog '$CatalogName' " -ForegroundColor Yellow
    Invoke-RestMethod -Headers $authHeader -body $body -Uri $uri -Method Post -ContentType "application/json"
}
else {
    Write-Host "Resource '$ResourceName' already exists under the catalog '$CatalogName'" -ForegroundColor Green
}
$resourceID = ((Invoke-RestMethod -Headers $authHeader -Uri $uriChecker -Method Get).value | Where-Object { $_.displayName -eq $ResourceName }).id
#endregion

#region Access Package
Write-Host "Working on Access Packages...." -ForegroundColor Cyan

$uri = $mainURI + 'accessPackages'
$packageChecker = (Invoke-RestMethod -Headers $authHeader -Uri $uri -Method GEt).value | Where-Object { $_.CatalogID -eq $CatalogId -and $_.DisplayName -eq $packageName }
if ($null -eq $packageChecker) {
    $body = @{
        catalogId           = $CatalogId
        displayName         = $packageName
        description         = $packageName
        isHidden            = "false"
        isRoleScopesVisible = "false"
    }
    $body = $body | ConvertTo-Json -Depth 10
    Write-Host "Adding access package '$packageName' to catalog '$CatalogName' " -ForegroundColor Yellow
    Invoke-RestMethod -Headers $authHeader -body $body -Uri $uri -Method Post -ContentType "application/json"
}
else {
    Write-Host "Acecss Package '$packageName' already exists under the catalog '$CatalogName'" -ForegroundColor Green
}
$packageID = ((Invoke-RestMethod -Headers $authHeader -Uri $uri -Method GEt).value | Where-Object { $_.CatalogID -eq $CatalogId -and $_.DisplayName -eq $packageName }).id

#endregion

#region Resource role
Write-Host "Working on Resource Roles...." -ForegroundColor Cyan

$roleUri = $mainURI + "accessPackageCatalogs/$catalogid/accessPackageResourceRoles`?`$filter=(originSystem+eq+%27AadGroup%27+and+accessPackageResource/id+eq+%27$resourceID%27+and+displayName+eq+%27Member%27)&`$expand=accessPackageResource"
$roleID = (Invoke-RestMethod -Uri $roleUri -Headers $authHeader -Method get).value.originId
$uri = $mainUri + "accessPackages/$packageID/accessPackageResourceRoleScopes"
$body = @{
    accessPackageResourceRole  = @{
        originId              = $roleID
        displayName           = "Member"
        originSystem          = "AadGroup"
        accessPackageResource = @{
            id           = $resourceID 
            resourceType = "Security Group"
            originId     = $groupID
            originSystem = "AadGroup"         
        }
    }
    accessPackageResourceScope = @{
        originId     = $groupID 
        originSystem = "AadGroup"      
    }
}
$body = $body | ConvertTo-Json -Depth 10
Write-Host "Setting 'Member' Role for '$ResourceName' under '$packageName'" -ForegroundColor Yellow
Invoke-RestMethod -Headers $authHeader -body $body -Uri $uri -Method Post -ContentType "application/json"
#endregion

#region Policy
Write-Host "Working on Policy...." -ForegroundColor Cyan
$BackupApproverUpnId = (get-azureaduser -SearchString $BackupApproverUPN).objectId
$uri = $mainURI + 'accessPackageAssignmentPolicies'
$policyChecker = (Invoke-RestMethod -Uri $uri -Headers $authHeader -Method get).value | Where-Object { $_.DisplayName -eq $externalPolicyName }
if ($null -ne $ExternalPolicyName) {
    if ($null -eq $policyChecker) {
        $body = @{
            accessPackageId         = $packageID
            displayName             = $externalPolicyName
            description             = $externalPolicyName
            durationInDays          = 30
            expirationDateTime      = "2021-07-16T00:00:00Z"
            requestorSettings       = @{
                scopeType         = "SpecificConnectedOrganizationSubjects"
                acceptRequests    = $true    
                allowedRequestors = @(
                    @{
                        '@odata.type' = '#microsoft.graph.connectedOrganizationMembers'
                        isBackup      = $false
                        id            = $conenctedOrganisationID
                        description   = $ConnectedOrganisationDisplayName
                    }
                )
            }
            requestApprovalSettings = @{
                isApprovalRequired               = $true
                isApprovalRequiredForExtension   = $true
                isRequestorJustificationRequired = $true
                approvalMode                     = 'SingleStage'
                approvalStages                   = @(
                    @{
                        approvalStageTimeOutInDays      = 14
                        isApproverJustificationRequired = $true
                        isEscalationEnabled             = $true
                        escalationTimeInMinutes         = 11520
                        primaryApprovers                = @(
                            @{
                                '@odata.type' = '#microsoft.graph.internalSponsors'
                            }
                        )
                        escalationApprovers             = @(
                            @{
                                isBackup      = $true
                                '@odata.type' = '#microsoft.graph.singleUser'
                                id            = $BackupApproverUpnId
                            }
                        )
                    }
                )
            }
            accessReviewSettings    = @{
                isEnabled      = $true
                recurrenceType = 'monthly'
                reviewerType   = 'Reviewers'
                startDateTime  = "2021-06-28T00:00:00.998Z"
                durationInDays = 14
                reviewers      = @(
                    @{
                        '@odata.type' = '#microsoft.graph.singleUser'
                        id            = $BackupApproverUpnId
                    }
                )
            }
        }

        $body = $body | ConvertTo-Json -Depth 10
        Write-Host "Adding new policy '$externalPolicyName' to access package '$packageName'" -ForegroundColor Yellow
        Invoke-RestMethod -Headers $authHeader -body $body -Uri $uri -Method Post -ContentType "application/json"
    }
    else {
        Write-Host "Policy '$externalPolicyName' already exists under access package '$packageName'" -ForegroundColor Green
    }
}

if ($null -ne $InternalPolicyName) {
    if ($null -eq $policyChecker) {
        $body = @{
            accessPackageId         = $packageID
            displayName             = $InternalPolicyName
            description             = $InternalPolicyName
            requestorSettings       = @{
                scopeType         = "AllExistingDirectoryMemberUsers"
                acceptRequests    = $true
                allowedRequestors = @()
            }            
            requestApprovalSettings = @{
                isApprovalRequired               = $true
                isApprovalRequiredForExtension   = $false
                isRequestorJustificationRequired = $true
                approvalMode                     = 'SingleStage'
                approvalStages                   = @(
                    @{
                        approvalStageTimeOutInDays      = 14
                        isApproverJustificationRequired = $true
                        isEscalationEnabled             = $false
                        escalationTimeInMinutes         = 0
                        primaryApprovers                = @(
                            @{
                                '@odata.type' = '#microsoft.graph.singleUser'
                                id            = $BackupApproverUpnId
                            }
                        )
                    }
                )
            }
            accessReviewSettings    = @{
                isEnabled      = $true
                recurrenceType = 'monthly'
                reviewerType   = 'Reviewers'
                startDateTime  = "2021-06-28T00:00:00.998Z"
                durationInDays = 14
                reviewers      = @(
                    @{
                        '@odata.type' = '#microsoft.graph.singleUser'
                        id            = $BackupApproverUpnId
                    }
                )
            }
        }

        $body = $body | ConvertTo-Json -Depth 10
        Write-Host "Adding new policy '$InternalPolicyName' to access package '$packageName'" -ForegroundColor Yellow
        Invoke-RestMethod -Headers $authHeader -body $body -Uri $uri -Method Post -ContentType "application/json"
    }
    else {
        Write-Host "Policy '$InternalPolicyName' already exists under access package '$packageName'" -ForegroundColor Green
    }
}

#endregion

Write-Host "Script run finished with the following parameters" -ForegroundColor Cyan
$output
Stop-Transcript
