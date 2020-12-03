---
title: Microsoft Defender for Identity configure detection exclusions and honeytoken accounts
description: Configuration of detection exclusions and honeytoken user accounts.
ms.date: 10/26/2020
ms.topic: how-to
---

# Configure detection exclusions and honeytoken accounts

[!INCLUDE [Product long](includes/product-long.md)] enables the exclusion of specific IP addresses or users from a number of detections.

For example, a **DNS Reconnaissance exclusion** could be a security scanner that uses DNS as a scanning mechanism. The exclusion helps [!INCLUDE [Product short](includes/product-short.md)] ignore such scanners.

[!INCLUDE [Product short](includes/product-short.md)] also enables the configuration of honeytoken accounts, which are used as traps for malicious actors - any authentication associated with these honeytoken accounts (normally dormant), triggers an alert.

To configure, follow these steps:

1. From the [!INCLUDE [Product short](includes/product-short.md)] portal, click on the settings icon and select **Configuration**.

    ![[!INCLUDE [Product short](includes/product-short.md)] configuration settings](media/config-menu.png)

1. Under **Detection**, click **Entity tags**.

1. Under **Honeytoken accounts**, enter the Honeytoken account name and click the **+** sign. The Honeytoken accounts field is searchable and automatically displays entities in your network. Click **Save**.

    ![Honeytoken](media/honeytoken-sensitive.png)

1. Click **Exclusions**. Enter a user account or IP address to be excluded from the detection, for each type of threat.
1. Click the *plus* sign. The **Add entity** (user or computer) field is searchable and will autofill with entities in your network. For more information, see [Excluding entities from detections](excluding-entities-from-detections.md) and the [security alert guide](suspicious-activity-guide.md).

    ![Excluding entities from detections](media/exclusions.png)

1. Click **Save**.

Congratulations, you have successfully deployed [!INCLUDE [Product long](includes/product-long.md)]!

Check the attack timeline to view security alerts generated from detected activities and search for users or computers, and view their profiles.

[!INCLUDE [Product short](includes/product-short.md)] scanning starts immediately. Some detections, such as [Suspicious additions to sensitive groups](domain-dominance-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024), require a learning period and aren't available immediately after [!INCLUDE [Product short](includes/product-short.md)] deployment.The learning period for each alert is listed in the detailed [security alert guide](suspicious-activity-guide.md).

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] sizing tool](https://aka.ms/aatpsizingtool)
- [Configure event collection](configure-event-collection.md)
- [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](https://aka.ms/MDIcommunity)
