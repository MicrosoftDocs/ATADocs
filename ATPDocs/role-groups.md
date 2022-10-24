---
title: Microsoft Defender for Identity role groups for access management
description: Walks you through working with Microsoft Defender for Identity role groups.
ms.date: 10/24/2022
ms.topic: conceptual
---

# Microsoft Defender for Identity role groups

[!INCLUDE [Product long](includes/product-long.md)] offers role-based security to safeguard data according to an organization's specific security and compliance needs. [!INCLUDE [Product short](includes/product-short.md)] support three separate roles: Administrators, Users, and Viewers.

[!INCLUDE [Handle personal data](../includes/gdpr-intro-sentence.md)]

Role groups enable access management for [!INCLUDE [Product short](includes/product-short.md)]. Using role groups, you can segregate duties within your security team, and grant only the amount of access that users need to do their jobs. This article explains access management, [!INCLUDE [Product short](includes/product-short.md)] role authorization, and helps you get up and running with role groups in [!INCLUDE [Product short](includes/product-short.md)].

> [!NOTE]
> Any global administrator or security administrator on the tenant's Azure Active Directory is automatically a [!INCLUDE [Product short](includes/product-short.md)] administrator.

## Required permissions for the Microsoft 365 Defender experience

To access the Defender for Identity experience in [in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi), you need the following permissions:

|Actions in Microsoft 365 Defender|Required permissions|
|---|---|
|Create MDI Workspace|Member of one of the following Azure AD roles:<li>Global Administrator<li>Security Administrator|
|MDI Settings|Member of one of the following Azure AD roles:<li>Global Administrator<li>Security Administrator <br> **Or** <br> Member of one of the following Azure AD groups (after the MDI Workspace is created): <li>Azure ATP {instance name} Administrator <li>Azure ATP {instance name} Users|
|MDI security alerts and activities|Member of one of the Azure AD roles as required by [Microsoft 365 Defender](/microsoft-365/security/defender/m365d-permissions)<br> **Or** <br> Member of one of the following [Microsoft Defender for Cloud Apps internal roles](/defender-cloud-apps/manage-admins#built-in-admin-roles-in-defender-for-cloud-apps): <li>Global admin <li>Security reader <li>Compliance admin|
|MDI security assessments <br> (now part of Microsoft Secure Score)|[Permissions](/microsoft-365/security/defender/microsoft-secure-score#required-permissions) to access Microsoft Secure Score <br> **And** <br> Member of one of the following Azure AD groups (after the MDI Workspace is created): <li>Azure ATP {instance name} Administrator <li>Azure ATP {instance name} Users <li>Azure ATP {instance name} Viewers <br><br> **Note:** Users who are members of the Azure AD *Global Administrator* or *Security Administrator* roles, do not need the above group membership as the required permissions are inherited from the Azure AD role.|
  
## Types of Defender for Identity security groups

[!INCLUDE [Product short](includes/product-short.md)] provides three types of security groups: Azure ATP *(instance name)* Administrators, Azure ATP *(instance name)* Users, and Azure ATP *(instance name)* Viewers. The following table describes the type of access in Defender for Identity available for each role. Depending on which role you assign, various screens and options will be  unavailable for those users, as follows:

|Activity |Azure ATP *(instance name)* Administrators|Azure ATP *(instance name)* Users|Azure ATP *(instance name)* Viewers|
|----|----|----|----|
|Change status of Health Alerts|Available|Not available|Not available|
|Change status of Security Alerts (reopen, close, exclude, suppress)|Available|Available|Not available|
|Delete instance|Available|Not available|Not available|
|Download a report|Available|Available|Available|
|Login|Available|Available|Available|
|Share/Export security alerts (via email, get link, download details)|Available|Available|Available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Updates|Available|Not available|Not available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Entity tags (sensitive and honeytoken)|Available|Available|Not available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Exclusions|Available|Available|Not available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Language|Available|Available|Not available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Notifications (email and syslog)|Available|Available|Not available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Preview detections|Available|Available|Not available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Scheduled reports|Available|Available|Not available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Data sources (directory services, SIEM, VPN, Defender for Endpoint)|Available|Not available|Not available|
|Update [!INCLUDE [Product short](includes/product-short.md)] Configuration - Sensors (download, regenerate key, configure, delete)|Available|Not available|Not available|
|View entity profiles and security alerts|Available|Available|Available|

## Add and remove users

[!INCLUDE [Product short](includes/product-short.md)] uses Azure AD security groups as a basis for role groups. The role groups can be managed from the [Groups management page](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/GroupsManagementMenuBlade/AllGroups). Only Azure AD users can be added or removed from security groups.

## Unified role-based access control (RBAC)

You can now enable more granular role-based access control from the Microsoft 365 portal instead of using Defender for Identity's Azure AD groups. For more information, see [Custom roles in role-based access control for Microsoft 365 Defender](/microsoft-365/security/defender/custom-roles).

>[!NOTE]
>Once enabled, you can migrate existing Defender for Identity roles to the new format. However, if you change or add new roles, they must match these permissions to the role table to access the classic Defender for Identity experience.

| Equivalent Defender for Identity role | Minimum required Microsoft 365 unified RBAC permissions              |
| ------------------------------------- | ------------------------------------------------------------ |
| MDI Admin                             | microsoft.xdr/configuration/security/manage <br />microsoft.xdr/configuration/system/manage <br />microsoft.xdr/secops/securitydata/alerts/manage <br />microsoft.xdr/secops/securitydata/read |
| MDI User                              | microsoft.xdr/secops/securitydata/read <br />microsoft.xdr/configuration/system/read <br />microsoft.xdr/secops/securitydata/alerts/manage <br />microsoft.xdr/configuration/security/manage |
| MDI Viewer                            | microsoft.xdr/secops/securitydata/read <br />microsoft.xdr/configuration/system/read <br />microsoft.xdr/configuration/security/read |

## See also

> [!div class="step-by-step"]
> [« Directory Service accounts](directory-service-accounts.md)
> [Configure remote calls to SAM »](remote-calls-sam.md)
