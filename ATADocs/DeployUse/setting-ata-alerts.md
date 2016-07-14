---
# required metadata

title: Setting ATA Notifications | Microsoft ATA
description: Describes how to set ATA alerts so you are notified when suspicious activities are detected.
keywords:
author: rkarlin
manager: stevenpo
ms.date: 04/28/2016
ms.topic: article
ms.prod: identity-ata
ms.service: advanced-threat-analytics
ms.technology: security
ms.assetid: 14cb7513-5dc8-49cb-b3e0-94f469c443dd

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Setting ATA Notifications
ATA can notify you when it detects a suspicious activity, either by email or by using ATA event forwarding and forwarding the event to your SIEM/syslog server. Before selecting which notifications you want to receive, you have to [set up your email server and your Syslog server](setting-syslog-email-server-settings.md).

> [!NOTE]
> -   Email notifications include a link that will take the user directly to the suspicious activity that was detected. The host name portion of the link is taken from the setting of the ATA Console URL on the ATA Center page. By default, the ATA Console URL is the IP address selected during the installation of the ATA Center.  If you are going to configure email notifications it is recommended to use an FQDN as the ATA Console URL.
> -   Notifications are sent from the ATA Center to either the SMTP server and the Syslog server.

To receive email notifications, set the following:


1. In the ATA Console, select the settings option on the toolbar and select **Configuration**.
![ATA configuration settings icon](media/ATA-config-icon.JPG)

2. Select **Notifications**.
3. Under **Email notifications**, use the toggles to select to which notifications should be sent:


	- New suspicious activity is detected
	- New health issue is detected
	- New software update is available

4. Specify the recipients who will receive the notifications via email.

	[!Note:] Email alerts for suspicious activities are only sent when the suspicious activity is created.


5. Click **Save**.

To receive Syslog notifications, set the following:


1. In the ATA Console, select the settings option on the toolbar and select **Configuration**.
![ATA configuration settings icon](media/ATA-config-icon.JPG)

2. Select **Notifications**.
3. Under **Syslog notifications**, use the toggles to select to which notifications should be sent:


	- New suspicious activity is detected
	- Existing suspicious activity is updated
	- New health issue is detected
5. Click **Save**.
![ATA notification settings image](media/ATA-notification-settings.png)




## See Also
[Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
