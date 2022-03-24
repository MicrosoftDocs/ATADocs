---
title: Microsoft Defender for Identity role groups for access management
description: Walks you through working with Microsoft Defender for Identity role groups.
ms.date: 02/27/2020
ms.topic: conceptual
---

# Microsoft Defender for Identity role groups

[!INCLUDE [Product long](includes/product-long.md)] offers role-based security to safeguard data according to an organization's specific security and compliance needs. [!INCLUDE [Product short](includes/product-short.md)] support three separate roles: Administrators, Users, and Viewers.

[!INCLUDE [Handle personal data](../includes/gdpr-intro-sentence.md)]

Role groups enable access management for [!INCLUDE [Product short](includes/product-short.md)]. Using role groups, you can segregate duties within your security team, and grant only the amount of access that users need to do their jobs. This article explains access management, [!INCLUDE [Product short](includes/product-short.md)] role authorization, and helps you get up and running with role groups in [!INCLUDE [Product short](includes/product-short.md)].

> [!NOTE]
> Any global administrator or security administrator on the tenant's Azure Active Directory is automatically a [!INCLUDE [Product short](includes/product-short.md)] administrator.

## Required permissions for the Microsoft 365 Defender experience

To access the Defender for Identity experience in [in Microsoft 365 Defender](defender-for-identity-in-microsoft-365-defender.md), you need the following permissions:

- For Defender for Identity alerts and activities in Microsoft 365 Defender, ensure you have the sufficient Azure Active Directory roles or Microsoft Defender for Cloud Apps internal roles.  For details, see [Microsoft Defender for Identity integration prerequisites](/cloud-app-security/mdi-integration#prerequisites).

    >[!NOTE]
    >The currently supported Defender for Cloud Apps roles are **Global admin**, **Security reader**, and **Compliance admin.**

- For Defender for Identity settings in Microsoft 365 Defender, ensure that you have the sufficient Azure Active Directory roles or you're a member of the **Azure ATP (instance name) Administrators** or the **Azure ATP (instance name) Users** Azure AD groups.  For more information on the Azure AD groups, see [Microsoft Defender for Identity Azure AD groups](#types-of-defender-for-identity-security-groups).

- For security assessments, now part of Microsoft Secure Score, ensure that you have:

  - [Permissions](/microsoft-365/security/defender/microsoft-secure-score#required-permissions) to access Microsoft Secure Score
  - At minimum, [viewer permissions](#types-of-defender-for-identity-security-groups) for Microsoft Defender for Identity

## Types of Defender for Identity security groups

[!INCLUDE [Product short](includes/product-short.md)] provides three types of security groups: Azure ATP *(instance name)* Administrators, Azure ATP *(instance name)* Users, and Azure ATP *(instance name)* Viewers. The following table describes the type of access in the [!INCLUDE [Product short](includes/product-short.md)] portal available for each role. Depending on which role you assign, various screens and menu options in [!INCLUDE [Product short](includes/product-short.md)] portal are unavailable for those users, as follows:

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

When users try to access a page that isn't available for their role group, they're redirected to the [!INCLUDE [Product short](includes/product-short.md)] unauthorized page.

## Add and remove users

[!INCLUDE [Product short](includes/product-short.md)] uses Azure AD security groups as a basis for role groups. The role groups can be managed from the [Groups management page](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/GroupsManagementMenuBlade/All%20groups). Only Azure AD users can be added or removed from security groups.

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] sizing tool](<https://aka.ms/aatpsizingtool>)
- [[!INCLUDE [Product short](includes/product-short.md)] architecture](architecture.md)
- [Install [!INCLUDE [Product short](includes/product-short.md)]](install-step1.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
