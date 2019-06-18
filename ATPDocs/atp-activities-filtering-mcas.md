---
# required metadata

title: Azure Advanced Threat Protection activity filtering and policies in Microsoft Cloud App Security  | Microsoft Docs
description: Overview of Azure ATP activity filtering and policies with Microsoft Cloud App Security.
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 06/18/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 397e5a77-2bc7-454c-9fe5-649ebaab16b3

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Use Activity filters and create action policies with Azure ATP in Microsoft Cloud App Security 

This article is designed to help you understand how to filter and create action policies for Azure ATP activities using Microsoft Cloud App Security. 

For more information about how to complete your integration, see [Azure ATP Cloud App Security integration](https://docs.microsoft.com/cloud-app-security/aatp-integration/enable-azure-advanced-threat-protection).  

Using Azure ATP with Microsoft Cloud App Security offers activity analysis and alerts based on User and Entity Behavior Analytics (UEBA), identifying the riskiest behaviors in your enterprise, providing a comprehensive investigation priority score as well as activity filtering and customizable activity policies. 

## Prerequisites

For complete user investigation features across the hybrid environment, you must have:
- A valid license for Microsoft Cloud App Security
- A valid license for Azure ATP connected to your Active Directory instance

>[!NOTE]
>If you don't have a subscription for Cloud App Security, you can use the Cloud App Security portal to investigate Azure ATP alerts and deep dive on users and their on-premise managed activities however insights related to your cloud applications will remain unavailable.

## Filter Azure ATP activities in Cloud App Security  
 
Azure ATP activities can be accessed from the main Cloud App Security **Investigate** menu by selecting the **Activity log** submenu, or from the **Alerts** menu by status, category, severity, application, user name, or policy.  

To access Azure ATP activities by user:

1. Filter the **Alerts** queue using the USER NAME field. 
    ![Alerts queue](media/atp-mcas-alerts-queue.png)
1. Click the user name on any of the alerts in the resulting list to open the **User page** of the user you wish to investigate. 
    
1. Filter activities of the user using the available fields, or add a new filter rule using the + button.
    ![Alerts queue](media/atp-mcas-activity-filter.png)

## Create activity policies in Cloud App Security

After filtering activities and identifying activity policies you'd like to implement, or noncompliance within your organization, use the **Create Activity Policy** option from the filter menu to immediately create a new customized policy per user, device, or tenant. 

To create a new activity policy:

1. From any Activity log page, click the **New policy from search** button.  
    ![Create new activity policy](media/atp-mcas-activity-log.png)
1. Add a **Policy name**. 
    ![Create new activity policy -step 2](media/atp-mcas-create-policy.png)
1. Add a policy **Description**.  
1. Assign the severity of the policy.
1. Select a category for the policy.
1. Choose the filters to create for the policy.
1. Refine or add filters. 
1. Save and apply the new policy.  


## Next steps

Learn more about Investigation priority scoring and additional features of [Microsoft Cloud App Security](https://docs.microsoft.com/cloud-app-security/) functionality.
  
## Join the Community

Do you have more questions, or an interest in discussing Azure ATP and related security with others? Join the [Azure ATP Community](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection) today!




