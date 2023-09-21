---
title: Roles and permissions | Microsoft Defender for Identity
description: Learn about the role groups used with Microsoft Defender for Identity.
ms.date: 08/27/2023
ms.topic: conceptual
---

# What are Defender for Identity roles and permissions?

Microsoft Defender for Identity uses Microsoft 365's role-based access control (RBAC) to manage your user access, so that you can safeguard your data according to your organization's specific security and compliance needs.

Defender for Identity also supports built-in security groups to define user roles with your tenant's Azure Active Directory.

This article describes Defender for Identities access management and role authorization, helping you segregate duties within your security team, and granting only the amount of access that users need to do their jobs.

[!INCLUDE [gdpr-intro-sentence](../../includes/gdpr-intro-sentence.md)] <!--do we really need this?-->

## Permissions required for Defender for Identity in Microsoft 365 Defender

The following table lists the permissions required to access [Defender for Identity in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi), using either built-in Azure Active Directory role groups or Microsoft 365's RBAC.

| Actions in Microsoft 365 Defender     | Required permissions                                         |
| ------------------------------------- | ------------------- |
| **Create a Defender for Identity workspace**   | One of the following Azure AD roles: <br>- Global Administrator <br>- Security Administrator |
| **Configure Defender for Identity settings**    | One of the following Azure AD roles:<br>- Global Administrator<br>- Security Administrator <br><br> **Or** the following [unified RBAC permissions](#mapping-built-in-role-groups-to-microsoft-365s-unified-rbac):<br />- `Authorization and settings/Security settings/Read`<br/>- `Authorization and settings/Security settings/All permissions`<br/>- `Authorization and settings/System settings/Read`<br>- `Authorization and settings/System settings/All permissions` |
| **View Defender for Identity security alerts and activities**                           | One of the Azure AD roles required by [Microsoft 365 Defender](/microsoft-365/security/defender/m365d-permissions)<br><br> **Or** the following [unified RBAC permissions](#mapping-built-in-role-groups-to-microsoft-365s-unified-rbac):<br>- `Security operations/Security data/Alerts` (Manage)<br/>- `Security operations/Security data/Security data basics` (Read) |
| **View Defender for Identity security assessments in Microsoft Secure Score** | - [Permissions to access Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score#required-permissions) <br>- The following [unified RBAC permissions](#mapping-built-in-role-groups-to-microsoft-365s-unified-rbac): `Security operations/Security data/Security data basics` (Read)|
|**View Defender for Identity details in the Assets > Identities page**|One of the following:<br>- [Permissions to access Defender for Cloud Apps](/azure/defender-for-cloud/permissions) <br> One of the Azure AD roles as required by [Microsoft 365 Defender](/microsoft-365/security/defender/m365d-permissions) |

## Defender for Identity built-in security groups

Defender for Identity uses Azure AD security groups as a basis for role groups. Defender for Identity provides the following built-in security groups for your user roles:

- Azure ATP *(Workspace name)* Administrators
- Azure ATP *(Workspace name)* Users
- Azure ATP *(Workspace name)* Viewers

The following table describes the type of access in Defender for Identity available for each role:

|Activity |Azure ATP *(Workspace name)* Administrators|Azure ATP *(Workspace name)* Users|Azure ATP *(Workspace name)* Viewers|
|----|----|----|----|
|**Change health alert statuses**| ✔|-|-|
|**Change security alert statuses** <br>(reopen, close, exclude, suppress)| ✔| ✔|-|
|**Delete workspace**| ✔|-|-|
|**Download a report**| ✔| ✔| ✔|
|**Login**| ✔| ✔| ✔|
|**Share/Export security alerts** <br>(via email, get link, download details)| ✔| ✔| ✔|
|**Update Defender for Identity configuration - Updates**| ✔|-|-|
|**Update Defender for Identity configuration - Entity tags** <br>(sensitive and honeytoken)| ✔| ✔|-|
|**Update Defender for Identity configuration - Exclusions**| ✔| ✔|-|
|**Update Defender for Identity configuration - Language**| ✔| ✔|-|
|**Update Defender for Identity configuration - Notifications** <br>(email and syslog)| ✔| ✔|-|
|**Update Defender for Identity configuration - Preview detections**| ✔| ✔|-|
|**Update Defender for Identity configuration - Scheduled reports**| ✔| ✔|-|
|**Update Defender for Identity configuration - Data sources** <br>(directory services, SIEM, VPN, Defender for Endpoint)| ✔|-|-|
|**Update Defender for Identity configuration - Sensors** <br>(download, regenerate key, configure, delete)| ✔|-|-|
|**View entity profiles and security alerts**| ✔| ✔| ✔|

Manage your role groups from the Azure Active Directory [Groups management page](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/GroupsManagementMenuBlade/AllGroups). Only Azure AD users can be added or removed from security groups.


### Azure Active Directory mapping

The following table maps Azure Active Directory roles to their Defender for Identity roles.


|Azure Active Directory roles ....  |Are automatically mapped to the following Defender for Identity roles |
|---------|---------|
|- Global administrator <br>- Security administrator     |  Administrator       |
|- Security operator     |   User      |
|- Global reader<br>- Security reader     |  Viewer       |


## Mapping built-in role groups to Microsoft 365's unified RBAC

Microsoft 365's unified RBAC provides more granular options for defining user access than Defender for Identity's build-in security groups. Define unified RBAC in Microsoft 365 Defender. For example:

:::image type="content" source="../media/choose-permissions.png" alt-text="Screenshot of the Permissions page in Microsoft 365 Defender." lightbox="../media/choose-permissions.png":::

The following table maps the built-in Defender for Identity role to require permissions in Microsoft 365 Defender:

| Built-in Defender for Identity role | Minimum required Microsoft 365 unified RBAC permissions      |
| ------------------------------------- | ------------------------------------------------------------ |
|**Administrator**                             | - `Authorization and settings/Security settings/Read`<br>- `Authorization and settings/Security settings/All permissions`<br/>-`Authorization and settings/System settings/Read`<br/>-`Authorization and settings/System settings/All permissions`<br/>- `Security operations/Security data/Alerts` (manage)<br/>- `Security operations/Security data/Security data basics` (Read)<br/>- `Authorization and settings/Authorization/All permissions` <br>- `Authorization and settings/Authorization/Read` |
|**User**                              | - `Security operations/Security data/Security data basics` (Read)<br/>- `Authorization and settings/System settings/Read`<br/>- `Authorization and settings/Security settings/Read`<br/>- `Security operations/Security data/Alerts` (manage)<br/>- `microsoft.xdr/configuration/security/manage` |
|**Viewer**                            | - `Security operations/Security data/Security data basics` (Read)<br/>- `Authorization and settings/System settings/Read`<br/>- `Authorization and settings/Security settings/Read` |

For more information, see [Custom roles in role-based access control for Microsoft 365 Defender](/microsoft-365/security/defender/custom-roles).

### Migrating from built-in role groups

Legacy customers can migrate any Defender for Identity role groups to Microsoft 365 Defender.
 
Information included from the [Defender for Cloud Apps activity log](../privacy-compliance.md#data-sharing) may still contain Defender for Identity data, which adheres to existing Defender for Cloud Apps permissions. <!--is this still relevant? refers to the classic page. where's the new one?-->


## Next step

> [!div class="step-by-step"]
> [Configure remote calls to SAM »](remote-calls-sam.md)
