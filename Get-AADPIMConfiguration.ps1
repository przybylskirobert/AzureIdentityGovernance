<#
    .Description
    Script to review the PIM configuration for specific Azure AD Tenant.
    Robert Przybylski
    www.azureblog.pl
    2021
    .Example 
    .\Get-AADPimConfiguration.ps1 -TenantID "xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx" -OutputPath "C:\Temp"
#>

param(
    [Parameter(Position = 0, mandatory = $true)][string] $TenantID,
    [Parameter(Position = 1, mandatory = $true)][string] $OutputPath 
)

#Require AzureADPreview

$outputFolderTest = Test-Path $OutputPath
if ($outputFolderTest -eq $false) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

try {
    Import-module AzureADPreview 
}
catch {
    Install-Module AzureADPreview
}
Write-Host "Please log into the Azure AD" -ForegroundColor Green
Connect-azuread -TenantId $TenantID

$rolesConfiguration = @()
$pimRoles = Get-AzureADMSPrivilegedRoleDefinition -providerID aadRoles -resourceid $TenantID
foreach ($role in $pimRoles) {
    $roleID = $role.id
    $roleName = $role.DisplayName
    $roleSettings = Get-AzureADMSPrivilegedRoleSetting -ProviderId 'aadRoles' -Filter "ResourceID eq '$TenantID' and RoleDefinitionId eq '$RoleID'"
    $activation = $roleSettings.UserMemberSettings
    $assignement = $roleSettings.AdminEligibleSettings 
    $activeassignements = $roleSettings.AdminmemberSettings 
    Write-Host "Gathering configuration for role '$roleName'" -ForegroundColor Yellow
    $rolesConfiguration += $(New-Object PSObject -Property @{
            RoleName                           = $roleName; 
            RoleID                             = $roleID; 
            PermanentAssignement               = ($activation[0].Setting | ConvertFrom-Json).permanentAssignment ; 
            ActivationMaximumDurationInMinutes = ($activation[0].Setting | ConvertFrom-Json).maximumGrantPeriodInMinutes; 
            RequireMFA                         = ($activation[1].Setting | ConvertFrom-Json).mfaRequired; 
            RequireJustificationOnActivation   = ($activation[2].Setting | ConvertFrom-Json).required; 
            RequireTicketOnActivation          = ($activation[3].Setting | ConvertFrom-Json).ticketingRequired; 
            GroupApprovers1                     = try {(($activation[4].Setting | ConvertFrom-Json).Approvers | Where-Object { $_.Type -eq 'Group' })[0].DisplayName} catch {};
            UserApprover1                       = try {(($activation[4].Setting | ConvertFrom-Json).Approvers | Where-Object { $_.Type -eq 'User' })[0].DisplayName} catch {};;
            GroupApprovers2                     = try {(($activation[4].Setting | ConvertFrom-Json).Approvers | Where-Object { $_.Type -eq 'Group' })[1].DisplayName} catch {};
            UserApprover2                       = try {(($activation[4].Setting | ConvertFrom-Json).Approvers | Where-Object { $_.Type -eq 'User' })[1].DisplayName} catch {};;
            AllowPermanentEligibleAssignment   = ($assignement[0].Setting | ConvertFrom-Json).permanentAssignment;
            ExpireEligibleAssigmentsAfterDays  = ($assignement[0].Setting | ConvertFrom-Json).maximumGrantPeriodInMinutes / 1440;
            AllowPermanentActiveAssignment = ($activeassignements[0].Setting | ConvertFrom-Json).maximumGrantPeriodInMinutes / 1440;
            RequireMFAonActiveAssignment = ($activeassignements[1].Setting | ConvertFrom-Json).mfaRequired;
            RequireJustificationonActiveAssignment = ($activeassignements[2].Setting | ConvertFrom-Json).required
        }
    )
}
Write-Host "Exporting data to '$OutputPath\PIMConfiguration.csv'" -ForegroundColor Green
$rolesConfiguration | Export-Csv -Path $OutputPath\PIMConfiguration.csv -NoTypeInformatio