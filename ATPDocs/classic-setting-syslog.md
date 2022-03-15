---
title: Classic portal - Setting Syslog settings in Microsoft Defender for Identity
description: Classic portal - Describes how to have Microsoft Defender for Identity notify you (by email or by Defender for Identity event forwarding) when it detects suspicious activities
ms.date: 10/27/2020
ms.topic: how-to
---

# Classic portal: Integrate with Syslog

> [!NOTE]
> The experience described in this page can also be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender. The supporting documents for the new experience can be found [here](/microsoft-365/security/defender-identity/notifications#syslog-notifications). For more information about Microsoft Defender for Identity and when other features will be available in Microsoft 365 Defender, see [Microsoft Defender for Identity in Microsoft 365 Defender](defender-for-identity-in-microsoft-365-defender.md).

[!INCLUDE [Product long](includes/product-long.md)] can notify you when it detects suspicious activities by sending security and health alerts to your Syslog server through a nominated sensor.

> [!NOTE]
> To learn how to integrate Defender for Identity with Microsoft Sentinel, see [Microsoft 365 Defender integration with Microsoft Sentinel](/azure/sentinel/microsoft-365-defender-sentinel-integration).

Once you enable Syslog notifications, you can set the following:

|Field|Description|
|---------|---------------|
|sensor|Select a designated sensor to be responsible for aggregating all the Syslog events and forwarding them to your SIEM server.|
|Service endpoint|IP address or DNS name of the Syslog server and optionally change the port number (default 514).<br><br>You can configure only one Syslog endpoint.|
|Transport|Can be UDP, TCP, or TLS (Secured Syslog)|
|Format|This is the format that [!INCLUDE [Product short](includes/product-short.md)] uses to send events to the SIEM server - either RFC 5424 or RFC 3164.|

1. Before configuring Syslog notifications, work with your SIEM admin to find out the following information:

    - FQDN or IP address of the SIEM server
    - Port on which the SIEM server is listening
    - What transport to use: UDP, TCP, or TLS (Secured Syslog)
    - Format in which to send the data RFC 3164 or 5424

1. Open the [!INCLUDE [Product short](includes/product-short.md)] portal.
1. Click **Settings**.
1. From the **Notifications and Reports** submenu, select **Notifications**.
1. From the **Syslog Service** option, click **Configure**.
1. Select the **Sensor**.
1. Enter the **Service endpoint** URL.
1. Select the **Transport** protocol (TCP or UDP).
1. Select the format (RFC 3164 or RFC 5424).
1. Select **Send test Syslog message** and then verify the message is received in your Syslog infrastructure solution.
1. Click **Save**.

To review or modify your Syslog settings.

1. Click **Notifications**, and then, under **Syslog notifications** click **Configure** and enter the following information:

    ![[!INCLUDE [Product short.](includes/product-short.md)] Syslog server settings image](media/syslog.png)

1. You can select which events to send to your Syslog server. Under **Syslog notifications**, specify which notifications should be sent to your Syslog server - new security alerts, updated security alerts, and new health issues.

> [!NOTE]
>
> - If you plan to create automation or scripts for [!INCLUDE [Product short](includes/product-short.md)] SIEM logs, we recommend using the **externalId** field to identify the alert type instead of using the alert name for this purpose. Alert names may occasionally be modified, while the **externalId** of each alert is permanent. For more information, see [[!INCLUDE [Product short](includes/product-short.md)] SIEM log reference](cef-format-sa.md).
>
> - When working with Syslog in TLS mode, make sure to install the required certificates on the designated sensor.

## See Also

- [Working with sensitive accounts](manage-sensitive-honeytoken-accounts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
