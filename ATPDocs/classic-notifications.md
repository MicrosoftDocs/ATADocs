---
title: Classic portal - Set Microsoft Defender for Identity notifications
description: Classic portal - Describes how to set Microsoft Defender for Identity security alerts so you are notified when suspicious activities are detected.
ms.date: 01/18/2023
ms.topic: how-to
ROBOTS: NOINDEX
---

# Classic portal: Set Microsoft Defender for Identity notifications

> [!NOTE]
> The experience described in this page can also be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender. The supporting documents for the new experience can be found [here](/microsoft-365/security/defender-identity/notifications). For more information about Microsoft Defender for Identity and when other features will be available in Microsoft 365 Defender, see [Microsoft Defender for Identity in Microsoft 365 Defender](/microsoft-365/security/defender/microsoft-365-security-center-mdi).

Microsoft Defender for Identity can notify you when it detects a suspicious activity and issues a security alert or a health alert via email.

To receive notifications to a specific email address, set the following parameters:

1. In the Defender for Identity portal, select the settings option on the toolbar and select **Configuration**.

    ![[!INCLUDE [Product short.](includes/product-short.md)] configuration settings icon](media/config-menu.png)

1. Click **Notifications**.
1. Under **Mail notifications**, add email addresses for the notifications you want to receive - they can be sent for new alerts (suspicious activities) and new health issues.

    > [!NOTE]
    >
    > - Emails are only sent for notifications with defined email addresses.
    > - Email alerts for suspicious activities are only sent when the suspicious activity is created.

1. Click **Save**.

    ![[!INCLUDE [Product short.](includes/product-short.md)] notifications](media/notifications.png)

## See Also

- [Configure event collection](configure-event-collection.md)

- [Set Syslog settings](/defender-for-identity/notifications)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
