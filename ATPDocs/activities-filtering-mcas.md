---
title: Microsoft Defender for Identity activity filtering and policies in Microsoft Cloud App Security
description: Overview of Microsoft Defender for Identity activity filtering and policies with Microsoft Cloud App Security.
ms.date: 10/26/2020
ms.topic: how-to
---

# Use activity filters and create action policies with [!INCLUDE [Product long](includes/product-long.md)] in Microsoft Cloud App Security

This article is designed to help you understand how to filter and create action policies for [!INCLUDE [Product short](includes/product-short.md)] activities using Microsoft Cloud App Security.

For more information about how to complete your integration, see [[!INCLUDE [Product short](includes/product-short.md)] integration with Cloud App Security](/cloud-app-security/aatp-integration).

Using [!INCLUDE [Product short](includes/product-short.md)] with Microsoft Cloud App Security offers activity analysis and alerts based on User and Entity Behavior Analytics (UEBA), identifying the riskiest behaviors in your enterprise, providing a comprehensive investigation priority score, as well as activity filtering and customizable activity policies.

## Prerequisites

For complete user investigation features across the hybrid environment, you must have:

- A valid license for Microsoft Cloud App Security
- A valid license for [!INCLUDE [Product long](includes/product-long.md)] connected to your Active Directory instance

>[!NOTE]
>If you don't have a subscription for Cloud App Security, you can use the Cloud App Security portal to investigate [!INCLUDE [Product short](includes/product-short.md)] alerts and deep dive on users and their on-premise managed activities however insights related to your cloud applications will remain unavailable.

## Filter [!INCLUDE [Product short](includes/product-short.md)] activities in Cloud App Security

[!INCLUDE [Product short](includes/product-short.md)] activities can be accessed from the main Cloud App Security **Investigate** menu by selecting the **Activity log** submenu, or from the **Alerts** menu by status, category, severity, application, user name, or policy.

To access [!INCLUDE [Product short](includes/product-short.md)] activities by user:

1. Filter the **Alerts** queue using the USER NAME field.
    ![Filter alerts by username](media/mcas-alerts-queue.png)
1. Click the user name on any of the alerts in the resulting list to open the **User page** of the user you wish to investigate.

1. Filter activities of the user using the available fields, or add a new filter rule using the + button.
    ![Filter activities of the user](media/mcas-activity-filter.png)

## Create activity policies in Cloud App Security

After filtering activities and identifying activity policies you'd like to implement, or noncompliance within your organization, use the **Create new activity policy** option from the filter menu to immediately create a new customized policy per user, device, or tenant.

To create a new activity policy:

1. From any **Activity log** page, apply a filter (such as APP, User Name, Activity type) etc.
    - To filter to activities from [!INCLUDE [Product short](includes/product-short.md)] select the **Active Directory** option in the APP filter.
    ![Create new activity policy](media/mcas-create-new-policy.png)
1. Click the **New policy from search** button.
1. Add a **Policy name**.
    ![Create new activity policy -step 2](media/mcas-create-policy.png)
1. Add a policy **Description**.
1. Assign the **severity** of the policy.
1. Select a **category** for the policy.
1. Choose or modify filters to create and assign for the policy.
1. Refine or add more filters.
1. Save and apply the new policy.

## Next steps

Learn more about Investigation priority scoring and additional features of [Microsoft Cloud App Security](/cloud-app-security/) functionality.

## Join the Community

Do you have more questions, or an interest in discussing [!INCLUDE [Product short](includes/product-short.md)] and related security with others? Join the [[!INCLUDE [Product short](includes/product-short.md)] Community](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection) today!