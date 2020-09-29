---
# required metadata

title: Set Azure Advanced Threat Protection notifications
description: Describes how to set Azure ATP security alerts so you are notified when suspicious activities are detected.
keywords:
author: shsagir
ms.author: shsagir
manager: shsagir
ms.date: 09/29/2020
ms.topic: how-to
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 4308f03e-b2a7-4e38-a750-540ff94faa81

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---


# Set Azure ATP notifications

[!INCLUDE [Rebranding notice](includes/rebranding.md)]

Azure ATP can notify you when it detects a suspicious activity and issues a security alert or a health alert via email.

To receive notifications to a specific email address, set the following parameters:

1. In the Azure ATP portal, select the settings option on the toolbar and select **Configuration**.

    ![Azure ATP configuration settings icon](media/atp-config-menu.png)

1. Click **Notifications**.
1. Under **Mail notifications**, add email addresses for the notifications you want to receive - they can be sent for new alerts (suspicious activities) and new health issues.

    > [!NOTE]
    >
    > - Emails are only sent for notifications with defined email addresses.
    > - Email alerts for suspicious activities are only sent when the suspicious activity is created.

1. Click **Save**.

    ![Azure ATP notifications](media/atp-notifications.png)

## See Also

- [Configure event collection](configure-event-collection.md)

- [Set Syslog settings](setting-syslog.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
