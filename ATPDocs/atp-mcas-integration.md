---
# required metadata

title: Azure Advanced Threat Protection in Microsoft Cloud App Security  | Microsoft Docs
description: Overview of Azure ATP features within Microsoft Cloud App Security.
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 07/01/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 5169dffc-75c4-4eb0-b997-b5359cecda97

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Using Azure ATP with Microsoft Cloud App Security 


This article is designed to help you understand and navigate the enhanced investigation experience when using the Microsoft Cloud App Security portal with Azure ATP. 

Leveraging existing on-premise detections and abnormal behavior analytics, accessing Azure ATP using the Microsoft Cloud App Security portal provides the added ability to detect and alert on sensitive data exfiltration across your enterprise as well as filter activities and create actionable policies. This hybrid offering analyzes activity and alerts based on User and Entity Behavior Analytics (UEBA) to determine risky behaviors, and provides an  investigation priority score to streamline your incident response for compromised identities. 

In this article you'll learn:

> [!div class="checklist"]
> * Service overview
> * New ways to access Azure ATP
> * Licensing prerequisites
> * Where to find Azure ATP tracked activities in Cloud App Security

## Service overview

Integrating with Azure ATP, the Cloud App Security portal provides alerts and insights from:
- Microsoft Cloud App Security, which identifies attacks within a cloud session, covering not only Microsoft products but also third-party applications
- Azure Advanced Threat Protection, which uses machine learning and behavioral analytics to identify attacks across your on-premises network
- Azure Active Directory Identity Protection, which detects and proactively prevents user and sign-in risks to identities in the cloud

## Access Azure ATP

Choose to continue to use Azure ATP within the Azure ATP portal, or, you can access Azure ATP alerts and identity scoring using the Microsoft Cloud App Security portal. In either workflow, Azure ATP set-up and configuration tasks continue to be handled within the Azure ATP portal. 

 

## Prerequisites

For complete user investigation features across the hybrid environment, you must have:
- A valid license for Microsoft Cloud App Security
- A valid license for Azure ATP connected to your Active Directory instance
 
>[!NOTE]
>If you don't have a subscription for Cloud App Security, you will still be able to use the Cloud App Security portal to investigate Azure ATP alerts and deep dive on users and their on-premise managed activities, but you won't receive related insights from your cloud applications.

See [Azure ATP integration](https://docs.microsoft.com/cloud-app-security/aatp-integration) to learn how to quickly enable Azure ATP in Cloud App Security.  
 
## Azure ATP in Cloud App Security 

See the [Cloud App Security quickstart](https://docs.microsoft.com/cloud-app-security/getting-started-with-cloud-app-security) to familiarize yourself with the basics of using the Cloud App Security portal. 

Access your Azure ATP data and new hybrid features within Cloud App Security alerts, activities, and user pages. 

## Alerts

Azure ATP alerts are displayed within the Cloud App Security **Alerts** queue. Additional alert filtering options are available only when viewing alerts using Cloud App Security. Azure ATP alerts are filtered using the application filter to **Active Directory**. 

## Alert management
When using Azure ATP with Cloud app security, closing alerts in one service will not automatically close them in the other service. Decide where to manage and remediate alerts to avoid duplicated efforts. 

## SIEM notification

If both your services (Azure ATP and Cloud App Security) are currently configured to send alert notifications to a SIEM, after enabling Azure ATP integration in Cloud App Security, you'll start to receive duplicate SIEM notifications for the same alert. One alert will be issued from each service and they will have different alert IDs. To avoid duplication and confusion, decide where you intend to perform alert management, and then stop SIEM notifications being sent from the other service.  

## Activities

Azure ATP alerts are displayed within the Cloud App Security **Activity log**. Additional activity filtering options and features are available only when viewing alerts using Cloud App Security. See [Azure ATP activities using Microsoft Cloud App Security](https://docs.microsoft.com/azure-advanced-threat-protection/atp-activities-filtering-mcas) to learn how to filter and create new activity policies.  

## User pages 

User pages contain the [Investigation Priority Score](https://docs.microsoft.com/cloud-app-security/tutorial-ueba) of each user and an activity log of all actions. 

To access a user page of a system user:
1. Open **Alerts** from the main menu.
1. Select and filter the alerts queue for a specific user by using the **User Name** field.

 or

1. From the **Investigate** menu, select **Activity log**. 
1. Filter the Activity log queue by user. 

    ![Activity log](media/atp-mcas-activity-filter.png)

## Next steps

See [Azure ATP activities using Microsoft Cloud App Security](https://docs.microsoft.com/azure-advanced-threat-protection/atp-activities-filtering-mcas) to learn how to filter and create new activity policies. 
  
## Join the Community

Do you have more questions, or an interest in discussing Azure ATP and related security with others? Join the [Azure ATP Community](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection) today!




