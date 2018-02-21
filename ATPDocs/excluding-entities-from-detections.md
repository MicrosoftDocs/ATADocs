---
# required metadata

title: Excluding entities from detections in Azure Advanced Threat Protection | Microsoft Docs
description: Describes how to stop Azure ATP from detecting specific entity activities as suspicious
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/21/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: cae3ed45-8fbc-4f25-ba24-3cc407c6ea93

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



# Excluding entities from detections
This article explains how to exclude entities from triggering alerts in order to minimize true benign positives but at the same time, make sure you catch the true positives. In order to keep Azure ATP from being noisy about activities that, from specific users, may be part of your normal rhythm of business, you can quiet - or exclude - specific entities from raising alerts.

For example, if you have a security scanner that does DNS recon or an admin who remotely runs scripts on the domain controller - and these are sanctioned activities whose intent is part of the normal IT operations in your organization. For more information about Azure ATP detections to help you decide which entities to exclude, see the [Suspicious activities guide](suspicious-activity-guide.md).

To exclude entities from raising alerts in Azure ATP:

There are two ways in which you can exclude entities, from the suspicious activity itself, or from the **Exclusions** tab on the **Configuration** page.

- **From the suspicious activity**: In the Suspicious activity time line, when you receive an alert on an activity for a user or computer or IP address that is allowed to perform the particular activity and may do so frequently, right-click the three dots at the end of the row for the suspicious activity on that entity, and select **Close and exclude**. <br></br>This adds the user, computer, or IP address to the exclusions list for that suspicious activity. It  closes the suspicious activity and it is no longer listed in the **Open** events list in the **Suspicious activity timeline**.

    ![Exclude entity](./media/exclude-in-sa.png)

- **From the Configuration page**:  To review or modify any exclusions: under **Configuration**, click **Exclusions** and then select the suspicious activity, such as **DNS reconnaissance**.

    ![Exclusion configuration](./media/exclusions.png)

To add an entity from the **Exclusions** configuration: enter the entity name and then click the plus, and then click **Save** at the bottom of the page.

To remove an entity from the **Exclusions** configuration: click the minus next to the entity name and then click **Save** at the bottom of the page.

It is recommended that you add exclusions to detections only after you get alerts of the type and determine that they are true benign positives. 

> [!NOTE]
> For your protection, not all detections provide the possibility to set exclusions. 

Some of the detections provide tips that help you decide what to exclude. 

Each exclusion depends on the context, in some you can set users while for others you can set computers or IP addresses. 

When you have the possibility of excluding an IP address or a computer, you can exclude one or the other - you don’t need to provide both.

> [!NOTE]
> The configuration pages can only be modified by Azure ATP admins.


## See Also

- [Integrating with Windows Defender ATP](integrate-wd-atp.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)