---
# required metadata

title: Azure Advanced Threat Protection role groups for access management | Microsoft Docs
description: Walks you through working with Azure ATP role groups.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 6/26/2018
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
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

*Applies to: Azure Advanced Threat Protection*




# Azure ATP role groups

Azure ATP offers role-based security to safeguard data according to an organization's specific security and compliance needs. Azure ATP support three separate roles: Administrators, Users and Viewers. 

[!INCLUDE [Handle personal data](../includes/gdpr-intro-sentence.md)]

Role groups enable access management for Azure ATP. Using role groups, you can segregate duties within your security team, and grant only the amount of access that users need to perform their jobs. This article explains access management and Azure ATP role authorization, and helps you get up and running with role groups in ATP.

> [!NOTE]
> Any global administrator or security administrator on the tenant's Azure Active Directory is automatically an Azure ATP administrator.

## Accessing the workspace management portal

Access to the workspace management portal (portal.atp.azure.com) can only be accomplished by an Azure AD user who has the directory role of global administrator or security administrator. After you enter the portal, you can create the different workspaces. For each workspace, the Azure ATP service creates three security groups in your Azure Active Directory tenant: Administrators, Users, Viewers. 

> [!NOTE]
> Access to the Azure ATP workspace portal is only granted to users within Azure AD security groups for that workspace, and global admins and security admins.


## Types of Azure ATP security groups 

Azure ATP introduces three types of security group: Azure ATP *workspace name* Administrators, Azure ATP *workspace name* Users, and Azure ATP *workspace name* Viewers. The following table describes the type of access in the Azure ATP workspace portal available per role. Depending on which role you assign, various screens and menu options in Azure ATP workspace portal are not available, as follows:

|Activity |Azure ATP *workspace name* Administrators|Azure ATP *workspace name* Users|Azure ATP *workspace name* Viewers|
|----|----|----|----|
|Login|Available|Available|Available|
|Change status of Suspicious Activities|Available|Available|Not available|
|Share/Export suspicious activity via email/get link|Available|Available|Available|
|Change status of Monitoring Alerts|Available|Not available|Not available|
|Update Azure ATP Configuration|Available|Not available|Not available|
|sensor – Add|Available|Not available|Not available|
|sensor – Delete |Available|Not available|Not available|
|Monitored DC – Add |Available|Not available|Not available|
|Monitored DC – Delete|Available|Not available|Not available|
|View alerts and suspicious activities|Available|Available|Available|


When users try to access a page that is not available for their role group, they are redirected to the Azure ATP unauthorized page. 

## Add and remove users 

Azure ATP uses Azure AD security groups as a basis for role groups. The role groups can be managed from [https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/UserManagementMenuBlade/All groups](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/UserManagementMenuBlade/All%20groups). Only AAD users can be added or removed from security groups. 


## See Also
- [ATA sizing tool](http://aka.ms/aatpsizingtool)
- [ATA architecture](atp-architecture.md)
- [Install ATA](install-atp-step1.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)

