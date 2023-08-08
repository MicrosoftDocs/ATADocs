---
title: Role groups 
description: Walks you through working with Microsoft Defender for Identity role groups.
ms.date: 01/29/2023
ms.topic: conceptual
---

# Microsoft Defender for Identity role groups

Microsoft Defender for Identity offers role-based security to safeguard data according to an organization's specific security and compliance needs. Defender for Identity support three separate roles: Administrators, Users, and Viewers.

Role groups enable access management for Defender for Identity. Using role groups, you can segregate duties within your security team, and grant only the amount of access that users need to do their jobs. This article explains access management, Defender for Identity role authorization, and helps you get up and running with role groups in Defender for Identity.

> [!NOTE]
> Any global administrator or security administrator on the tenant's Azure Active Directory is automatically a Defender for Identity administrator.

## Unified role-based access control (RBAC)

You can now enable more granular role-based access control from the Microsoft 365 portal instead of using Defender for Identity's Azure AD groups. For more information, see [Custom roles in role-based access control for Microsoft 365 Defender](/microsoft-365/security/defender/custom-roles).

> [!NOTE]
> Once enabled, you can migrate existing Defender for Identity roles to the new format. However, if you change or add new roles, they must match these permissions to the role table to access the classic Defender for Identity experience.

:::image type="content" source="media/choose-permissions.png" alt-text="Select permissions from each permission group." lightbox="media/choose-permissions.png":::

| Equivalent Defender for Identity role | Minimum required Microsoft 365 unified RBAC permissions      |
| ------------------------------------- | ------------------------------------------------------------ |
|MDI Admin                             | Authorization and settings/Security settings/Read<br/>Authorization and settings/Security settings/All permissions<br/>Authorization and settings/System settings/Read<br/>Authorization and settings/System settings/All permissions<br/>Security operations/Security data/Alerts (manage)<br/>Security operations/Security data /Security data basics (Read)<br/>Authorization and settings/Authorization/All permissions <br> Authorization and settings/Authorization/Read |
|MDI User                              | Security operations/Security data /Security data basics (Read)<br/>Authorization and settings/System settings/Read<br/>Authorization and settings/Security settings/Read<br/>Security operations/Security data/Alerts (manage)<br/>microsoft.xdr/configuration/security/manage |
|MDI Viewer                            | Security operations/Security data /Security data basics (Read)<br/>Authorization and settings/System settings/Read<br/>Authorization and settings/Security settings/Read |

> [!NOTE]
> Information included from the [Defender for Cloud Apps activity log](classic-mcas-integration.md#activities) may still contain Defender for Identity data which adheres to existing Defender for Cloud Apps permissions.

## Required permissions for the Microsoft 365 Defender experience

To access the Defender for Identity experience in [in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi), you need the following permissions:

| Actions in Microsoft 365 Defender                            | Required permissions                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Create MDI Workspace                                         | Member of one of the following Azure AD roles:<li>Global Administrator<li>Security Administrator |
| MDI Settings                                                 | Member of one of the following Azure AD roles:<li>Global Administrator<li>Security Administrator <br> **Or** <br> [Unified RBAC permissions](#unified-role-based-access-control-rbac):<br /><li>Authorization and settings/Security settings/Read<br/> <li>Authorization and settings/Security settings/All permissions<br/> <li>Authorization and settings/System settings/Read<br/><li> Authorization and settings/System settings/All permissions |
| MDI security alerts and activities                           | Member of one of the Azure AD roles as required by [Microsoft 365 Defender](/microsoft-365/security/defender/m365d-permissions)<br> **Or** <br> [Unified RBAC permissions](#unified-role-based-access-control-rbac):<br /><li>Security operations/Security data/Alerts (Manage)<br/><li>Security operations/Security data /Security data basics (Read) |
| MDI security assessments <br> (now part of Microsoft Secure Score) | [Permissions](/microsoft-365/security/defender/microsoft-secure-score#required-permissions) to access Microsoft Secure Score <br> **And** <br> [Unified RBAC permissions](#unified-role-based-access-control-rbac): <br><li>Security operations/Security data /Security data basics (Read)|
|Assets / Identities page|[Permissions](/azure/defender-for-cloud/permissions) to access Defender for Cloud Apps <br> **or** <br> Member of one of the Azure AD roles as required by [Microsoft 365 Defender](/microsoft-365/security/defender/m365d-permissions) |

## Types of Defender for Identity security groups

Defender for Identity provides three types of security groups: Azure ATP *(Workspace name)* Administrators, Azure ATP *(Workspace name)* Users, and Azure ATP *(Workspace name)* Viewers. The following table describes the type of access in Defender for Identity available for each role. Depending on which role you assign, various screens and options will be  unavailable for those users, as follows:

|Activity |Azure ATP *(Workspace name)* Administrators|Azure ATP *(Workspace name)* Users|Azure ATP *(Workspace name)* Viewers|
|----|----|----|----|
|Change status of Health Alerts|Available|Not available|Not available|
|Change status of Security Alerts (reopen, close, exclude, suppress)|Available|Available|Not available|
|Delete Workspace|Available|Not available|Not available|
|Download a report|Available|Available|Available|
|Login|Available|Available|Available|
|Share/Export security alerts (via email, get link, download details)|Available|Available|Available|
|Update Defender for Identity Configuration - Updates|Available|Not available|Not available|
|Update Defender for Identity Configuration - Entity tags (sensitive and honeytoken)|Available|Available|Not available|
|Update Defender for Identity Configuration - Exclusions|Available|Available|Not available|
|Update Defender for Identity Configuration - Language|Available|Available|Not available|
|Update Defender for Identity Configuration - Notifications (email and syslog)|Available|Available|Not available|
|Update Defender for Identity Configuration - Preview detections|Available|Available|Not available|
|Update Defender for Identity Configuration - Scheduled reports|Available|Available|Not available|
|Update Defender for Identity Configuration - Data sources (directory services, SIEM, VPN, Defender for Endpoint)|Available|Not available|Not available|
|Update Defender for Identity Configuration - Sensors (download, regenerate key, configure, delete)|Available|Not available|Not available|
|View entity profiles and security alerts|Available|Available|Available|

## Add and remove users

Defender for Identity uses Azure AD security groups as a basis for role groups. The role groups can be managed from the [Groups management page](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/GroupsManagementMenuBlade/AllGroups). Only Azure AD users can be added or removed from security groups.

## See also

> [!div class="step-by-step"]
> [« Directory Service accounts](directory-service-accounts.md)
> [Configure remote calls to SAM »](remote-calls-sam.md)


