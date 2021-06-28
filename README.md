# AzureIdentityGovernance repository
Hi there!
This is my place where I'm putting all the scripts and config files regarding Azure AD Identity Governance

## Scripts Overview

Scripts were created based on the BETA API for Identity Governance.
- [Set-ELMSettings.ps1](https://github.com/przybylskirobert/AzureIdentityGovernance/blob/master/Set-ELMSettings.ps1) - Script used configure Entitlement Management core Settings
- [New-ELMDeployment.ps1](https://github.com/przybylskirobert/AzureIdentityGovernance/blob/master/New-ELMDeployment.ps1) - Script that deploys Conncted Organisation, Catalog, Catalog Resources, Access Package Resources, Access Package and Access Package Policies
- [New-TermsOfUse.ps1](https://github.com/przybylskirobert/AzureIdentityGovernance/blob/master/New-TermsOfUse.ps1) - Script that configures Terms of Use - manual file upload is required - not fixed yet.
- [CNew-CaToUPolicy.ps1](https://github.com/przybylskirobert/AzureIdentityGovernance/blob/master/New-CaToUPolicy.ps1)  - Script that creates CA Policy for External and Guest Users with exclusion for BGA account and requires MFA + ToU
