---
title: Microsoft Defender for Identity in Microsoft Defender for Cloud Apps
description: Overview of Microsoft Defender for Identity features within Microsoft Defender for Cloud Apps.
ms.date: 02/15/2023
ms.topic: how-to
ROBOTS: NOINDEX
---

# Using Microsoft Defender for Identity with Microsoft Defender for Cloud Apps

[!INCLUDE [automatic-redirect](../includes/automatic-redirect.md)]

This article is designed to help you understand how Microsoft Defender for Identity functionality is represented in the Microsoft Defender for Cloud Apps portal.

Leveraging existing on-premises detections and abnormal behavior analytics, accessing Defender for Identity using the Microsoft Defender for Cloud Apps portal provides the ability to detect and alert on sensitive data exfiltration across your enterprise. This hybrid offering analyzes activity and alerts based on User and Entity Behavior Analytics (UEBA) to determine risky behaviors, and provides an investigation priority score to streamline your incident response for compromised identities. 

In this article you'll learn:

> [!div class="checklist"]
>
> - Service overview
> - New ways to access Defender for Identity
> - Licensing prerequisites
> - Where to find Defender for Identity tracked activities in Defender for Cloud Apps

## Service overview

Integrating with Defender for Identity, the Defender for Cloud Apps portal provides alerts and insights from:

- Microsoft Defender for Cloud Apps, which identifies attacks within a cloud session, covering not only Microsoft products but also third-party applications
- Microsoft Defender for Identity, which uses machine learning and behavioral analytics to identify attacks across your on-premises network
- Azure Active Directory Identity Protection, which detects and proactively prevents user and sign-in risks to identities in the cloud

## Prerequisites

For complete user investigation features across the hybrid environment, you must have:

- A valid license for Microsoft Defender for Cloud Apps
- A valid license for Microsoft Defender for Identity connected to your Active Directory instance

>[!NOTE]
>
> - If you don't have a subscription for Defender for Cloud Apps, you will still be able to use the Defender for Cloud Apps portal to investigate Defender for Identity alerts and deep dive on users and their on-premises managed activities, but you won't receive related insights from your cloud applications.
> - Defender for Identity administrators may require new permissions to access Defender for Cloud Apps. To learn how to assign permissions to Defender for Cloud Apps, see [Manage admin access](/cloud-app-security/manage-admins).

See [Defender for Identity integration](/cloud-app-security/mdi-integration) to learn how to quickly enable Defender for Identity in Defender for Cloud Apps.

## Defender for Identity in Defender for Cloud Apps

See the [Defender for Cloud Apps quickstart](/cloud-app-security/getting-started-with-cloud-app-security) to familiarize yourself with the basics of using the Defender for Cloud Apps portal.

## Alerts

Defender for Identity alerts are displayed within the Defender for Cloud Apps **Alerts** queue. Additional alert filtering options are available only when viewing alerts using Defender for Cloud Apps. Defender for Identity alerts are filtered using the application filter to **Active Directory**.

## Alert management

When using Defender for Identity with Defender for Cloud Apps, closing alerts in one service won't automatically close them in the other service. More specifically, closing alerts in Defender for Cloud Apps won't close them in Defender for Identity, but closing alerts in Defender for Identity will synchronize the closure in Defender for Cloud Apps. Decide where to manage and remediate alerts to avoid duplicated efforts.

## SIEM notification

If both your services (Defender for Identity and Defender for Cloud Apps) are currently configured to send alert notifications to a SIEM, after enabling Defender for Identity integration in Defender for Cloud Apps, you'll start to receive duplicate SIEM notifications for the same alert. One alert will be issued from each service and they'll have different alert IDs. To avoid duplication and confusion, decide where you intend to perform alert management, and then stop SIEM notifications being sent from the other service.

## Activities

Defender for Identity alerts are displayed within the Defender for Cloud Apps **Activity log**. Additional activity filtering options and features are available only when viewing alerts using Defender for Cloud Apps. See [Defender for Identity activities using Microsoft Defender for Cloud Apps](/defender-for-identity/classic-activities-filtering-mcas) to learn how to filter and create new activity policies.

## User pages

User pages contain the [Investigation Priority Score](/cloud-app-security/tutorial-ueba) of each user and an activity log of all actions.

To access a user page of a system user:

1. Open **Alerts** from the main menu. 
1. Select and filter the alerts queue for a specific user by using the **User Name** field.

 or

1. From the **Investigate** menu, select **Activity log**.
1. Filter the Activity log queue by user.

    ![Activity log.](media/mcas-activity-filter.png)

## Join the Community

Do you have more questions, or an interest in discussing Defender for Identity and related security with others? Join the [Defender for Identity Community](<https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection>) today!
