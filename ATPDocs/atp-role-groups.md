---
# required metadata

title: Azure Advanced Threat Protection role groups for access management | Microsoft Docs
description: Walks you through working with Azure ATP role groups.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 02/27/2020
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: effca0f2-fcae-4fca-92c1-c37306decf84

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Azure ATP role groups

Azure ATP offers role-based security to safeguard data according to an organization's specific security and compliance needs. Azure ATP support three separate roles: Administrators, Users and Viewers.

[!INCLUDE [Handle personal data](../includes/gdpr-intro-sentence.md)]

Role groups enable access management for Azure ATP. Using role groups, you can segregate duties within your security team, and grant only the amount of access that users need to perform their jobs. This article explains access management, Azure ATP role authorization, and helps you get up and running with role groups in Azure ATP.

> [!NOTE]
> Any global administrator or security administrator on the tenant's Azure Active Directory is automatically an Azure ATP administrator.

## Accessing the Azure ATP portal

Access to the Azure ATP portal (portal.atp.azure.com) can only be accomplished by an Azure AD user who has the directory role of global administrator or security administrator. After entering the portal with the required role, you can create your Azure ATP instance. Azure ATP service creates three security groups in your Azure Active Directory tenant: Administrators, Users, Viewers.

> [!NOTE]
> Access to the Azure ATP portal is granted only to users within the Azure ATP security groups, within your Azure Active Directory, as well as global and security admins of the tennant.

## Types of Azure ATP security groups

Azure ATP provides three types of security groups: Azure ATP *(instance name)* Administrators, Azure ATP *(instance name)* Users, and Azure ATP *(instance name)* Viewers. The following table describes the type of access in the Azure ATP portal available for each role. Depending on which role you assign, various screens and menu options in Azure ATP portal are unavailable for those users, as follows:

|Activity |Azure ATP *(instance name)* Administrators|Azure ATP *(instance name)* Users|Azure ATP *(instance name)* Viewers|
|----|----|----|----|
|Change status of Monitoring Alerts|Available|Not available|Not available|
|Change status of Security Alerts (re-open, close, exclude, suppress)|Available|Available|Not available|
|Delete instance|Available|Not available|Not available|
|Download a report|Available|Available|Available|
|Login|Available|Available|Available|
|Share/Export security alerts (via email, get link, download details)|Available|Available|Available|
|Update ATP Configuration - Updates|Available|Not available|Not available|
|Update ATP Configuration -Entity tags (sensitive and honeytoken)|Available|Available|Not available|
|Update ATP Configuration -Exclusions|Available|Available|Not available|
|Update ATP Configuration -Language|Available|Available|Not available|
|Update ATP Configuration -Notifications (email and syslog)|Available|Available|Not available|
|Update ATP Configuration -Preview detections|Available|Available|Not available|
|Update ATP Configuration -Scheduled reports|Available|Available|Not available|
|Update Azure ATP Configuration - Data sources (directory services, SIEM, VPN WD-ATP)|Available|Not available|Not available|
|Update Azure ATP Configuration - Sensors (download, regenerate key, configure, delete)|Available|Not available|Not available|
|View entity profiles and security alerts|Available|Available|Available|

When users try to access a page that is not available for their role group, they are redirected to the Azure ATP unauthorized page.

## Add and remove users

Azure ATP uses Azure AD security groups as a basis for role groups. The role groups can be managed from [https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/GroupsManagementMenuBlade/All%20groups](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/GroupsManagementMenuBlade/All%20groups). Only Azure AD users can be added or removed from security groups.

## See Also

- [ATP sizing tool](https://aka.ms/aatpsizingtool)
- [ATP architecture](atp-architecture.md)
- [Install Azure ATP](install-atp-step1.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
