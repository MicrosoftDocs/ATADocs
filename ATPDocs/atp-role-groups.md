---
# required metadata

title: Azure Advanced Threat Protection role groups for access management | Microsoft Docs
description: Walks you through working with Azure ATP role groups.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: effca0f2-fcae-4fca-92c1-c37306decf84

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*




# Azure ATP role groups

Role groups enable access management for ATP. Using role groups, you can segregate duties within your security team, and grant only the amount of access that users need to perform their jobs. This article explains access management and Azure ATP role authorization, and helps you get up and running with role groups in ATP.

> [!NOTE]
> Any local administrator on the Azure ATP cloud service is automatically a Microsoft Azure Advanced Threat Protection Administrator.

## Types of Azure ATP role groups 

Azure ATP introduces three types of Role group: Azure ATP Administrators, Azure ATP Users, and Azure ATP Viewers. The following table describes the type of access in Azure ATP available per role. Depending on which role you assign, various screens and menu options in Azure ATP are not available, as follows:

|Activity |Microsoft Azure Advanced Threat Protection Administrators|Microsoft Azure Advanced Threat Protection Users|Microsoft Azure Advanced Threat Protection Viewers|
|----|----|----|----|
|Login|Available|Available|Available|
|Provide Input for Suspicious Activities|Available|Available|Not available|
|Change status of Suspicious Activities|Available|Available|Not available|
|Share/Export suspicious activity via email/get link|Available|Available|Not available|
|Change status of Monitoring Alerts|Available|Available|Not available|
|Update Azure ATP Configuration|Available|Not available|Not available|
|Gateway – Add|Available|Not available|Not available|
|Gateway – Delete |Available|Not available|Not available|
|Monitored DC – Add |Available|Not available|Not available|
|Monitored DC – Delete|Available|Not available|Not available|
|View alerts and suspicious activities|Available|Available|Available|


When users try to access a page that is not available for their role group, they are redirected to the Azure ATP unauthorized page. 

## Add and remove users 

Azure ATP uses the local Windows groups as a basis for role groups. The role groups must be managed on the Azure ATP cloud service server.
To add or remove users, use the **Local Users and Groups** MMC (Lusrmgr.msc). On a domain joined machine, you can add domain accounts as well as local accounts. 

