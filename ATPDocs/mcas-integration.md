---
title: Microsoft Defender for Identity in Microsoft Cloud App Security
description: Overview of Microsoft Defender for Identity features within Microsoft Cloud App Security.
ms.date: 01/24/2021
ms.topic: how-to
---

# Using [!INCLUDE [Product long](includes/product-long.md)] with Microsoft Cloud App Security

This article is designed to help you understand and navigate the enhanced investigation experience when using the Microsoft Cloud App Security portal with [!INCLUDE [Product long](includes/product-long.md)].

Leveraging existing on-premise detections and abnormal behavior analytics, accessing [!INCLUDE [Product short](includes/product-short.md)] using the Microsoft Cloud App Security portal provides the added ability to detect and alert on sensitive data exfiltration across your enterprise as well as filter activities and create actionable policies. This hybrid offering analyzes activity and alerts based on User and Entity Behavior Analytics (UEBA) to determine risky behaviors, and provides an  investigation priority score to streamline your incident response for compromised identities.

In this article you'll learn:

> [!div class="checklist"]
>
> - Service overview
> - New ways to access [!INCLUDE [Product short](includes/product-short.md)]
> - Licensing prerequisites
> - Where to find [!INCLUDE [Product short](includes/product-short.md)] tracked activities in Cloud App Security

## Service overview

Integrating with [!INCLUDE [Product short](includes/product-short.md)], the Cloud App Security portal provides alerts and insights from:

- Microsoft Cloud App Security, which identifies attacks within a cloud session, covering not only Microsoft products but also third-party applications
- [!INCLUDE [Product long](includes/product-long.md)], which uses machine learning and behavioral analytics to identify attacks across your on-premises network
- Azure Active Directory Identity Protection, which detects and proactively prevents user and sign-in risks to identities in the cloud

## Access [!INCLUDE [Product short](includes/product-short.md)]

Choose to continue to use [!INCLUDE [Product short](includes/product-short.md)] within the [!INCLUDE [Product short](includes/product-short.md)] portal, or, you can access [!INCLUDE [Product short](includes/product-short.md)] alerts and identity scoring using the Microsoft Cloud App Security portal. In either workflow, [!INCLUDE [Product short](includes/product-short.md)] set-up and configuration tasks continue to be handled within the [!INCLUDE [Product short](includes/product-short.md)] portal.

## Prerequisites

For complete user investigation features across the hybrid environment, you must have:

- A valid license for Microsoft Cloud App Security
- A valid license for [!INCLUDE [Product long](includes/product-long.md)] connected to your Active Directory instance

>[!NOTE]
>
> - If you don't have a subscription for Cloud App Security, you will still be able to use the Cloud App Security portal to investigate [!INCLUDE [Product short](includes/product-short.md)] alerts and deep dive on users and their on-premise managed activities, but you won't receive related insights from your cloud applications.
> - [!INCLUDE [Product short](includes/product-short.md)] administrators may require new permissions to access Cloud App Security. To learn how to assign permissions to Cloud App Security, see [Manage admin access](/cloud-app-security/manage-admins).

See [[!INCLUDE [Product short](includes/product-short.md)] integration](/cloud-app-security/mdi-integration) to learn how to quickly enable [!INCLUDE [Product short](includes/product-short.md)] in Cloud App Security.

## [!INCLUDE [Product short](includes/product-short.md)] in Cloud App Security

See the [Cloud App Security quickstart](/cloud-app-security/getting-started-with-cloud-app-security) to familiarize yourself with the basics of using the Cloud App Security portal.

Access your [!INCLUDE [Product short](includes/product-short.md)] data and new hybrid features within Cloud App Security alerts, activities, and user pages.

## Alerts

[!INCLUDE [Product short](includes/product-short.md)] alerts are displayed within the Cloud App Security **Alerts** queue. Additional alert filtering options are available only when viewing alerts using Cloud App Security. [!INCLUDE [Product short](includes/product-short.md)] alerts are filtered using the application filter to **Active Directory**.

## Alert management

When using [!INCLUDE [Product short](includes/product-short.md)] with Cloud app security, closing alerts in one service will not automatically close them in the other service. More specifically, closing alerts in Cloud App Security will not close them in Defender for Identity, but closing alerts in Defender for Identity will synchronize the closure in Cloud App Security. Decide where to manage and remediate alerts to avoid duplicated efforts.

## SIEM notification

If both your services ([!INCLUDE [Product short](includes/product-short.md)] and Cloud App Security) are currently configured to send alert notifications to a SIEM, after enabling [!INCLUDE [Product short](includes/product-short.md)] integration in Cloud App Security, you'll start to receive duplicate SIEM notifications for the same alert. One alert will be issued from each service and they will have different alert IDs. To avoid duplication and confusion, decide where you intend to perform alert management, and then stop SIEM notifications being sent from the other service.

## Activities

[!INCLUDE [Product short](includes/product-short.md)] alerts are displayed within the Cloud App Security **Activity log**. Additional activity filtering options and features are available only when viewing alerts using Cloud App Security. See [[!INCLUDE [Product short](includes/product-short.md)] activities using Microsoft Cloud App Security](activities-filtering-mcas.md) to learn how to filter and create new activity policies.

## User pages

User pages contain the [Investigation Priority Score](/cloud-app-security/tutorial-ueba) of each user and an activity log of all actions.

To access a user page of a system user:

1. Open **Alerts** from the main menu.
1. Select and filter the alerts queue for a specific user by using the **User Name** field.

 or

1. From the **Investigate** menu, select **Activity log**.
1. Filter the Activity log queue by user.

    ![Activity log](media/mcas-activity-filter.png)

## Next steps

See [[!INCLUDE [Product short](includes/product-short.md)] activities using Microsoft Cloud App Security](activities-filtering-mcas.md) to learn how to filter and create new activity policies.

## Join the Community

Do you have more questions, or an interest in discussing [!INCLUDE [Product short](includes/product-short.md)] and related security with others? Join the [[!INCLUDE [Product short](includes/product-short.md)] Community](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection) today!
