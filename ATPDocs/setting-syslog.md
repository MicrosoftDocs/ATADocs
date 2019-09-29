---
# required metadata

title: Setting Syslog settings in Azure Advanced Threat Protection | Microsoft Docs
description: Describes how to have Azure ATP notify you (by email or by Azure ATP event forwarding) when it detects suspicious activities 
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 09/16/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: a2d29c9c-7ecb-4804-b74b-fde899b28648

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---



# Integrate with Syslog

> [!NOTE]
> The Azure ATP features explained on this page are also accessible using the new [portal](https://portal.cloudappsecurity.com).

Azure ATP can notify you when it detects suspicious activities and issue security alerts and health alerts by sending the notifications to your Syslog server. Alerts are sent from the Azure ATP sensor that detected the activity directly to the Syslog server. 


Once you enable Syslog notifications, you can set the following:

   |Field|Description|
   |---------|---------------|
   |sensor|Select a designated sensor to be responsible for aggregating all the Syslog events and forwarding them to your SIEM server.|
   |Service endpoint|FQDN of the Syslog server and optionally change the port number (default 514)|
   |Transport|Can be UDP, TCP, or TLS (Secured Syslog)|
   |Format|This is the format that Azure ATP uses to send events to the SIEM server - either RFC 5424 or RFC 3164.|

1. Before configuring Syslog notifications, work with your SIEM admin to find out the following information:

   -   FQDN or IP address of the SIEM server

   -   Port on which the SIEM server is listening

   -   What transport to use: UDP, TCP, or TLS (Secured Syslog)

   -   Format in which to send the data RFC 3164 or 5424

1. Open the Azure ATP portal. 
2. Click **Settings**.
3. From the **Notifications and Reports** sub menu, select **Notifications**. 
1. From the **Syslog Service** option, click **Configure**.
1. Select the **Sensor**. 
1. Enter the **Service endpoint** URL.
1. Select the **Transport** protocol (TCP or UDP). 
1. Select the format (RFC 3164 or RFC 5424). 
1. Select **Send text Syslog message** and then verify the message is received in your Syslog infrastructure solution. 
1. Click **Save**. 

To review or modify your Syslog settings.  

3. Click **Notifications**, and then, under **Syslog notifications** click **Configure** and enter the following information:

   ![Azure ATP Syslog server settings image](media/atp-syslog.png)

4. You can select which events to send to your Syslog server. Under **Syslog notifications**, specify which notifications should be sent to your Syslog server - new security alerts, updated security alerts, and new health issues.

> [!NOTE]
> If you plan to create automation or scripts for Azure ATP SIEM logs, we recommend using the **externalId** field to identify the alert type instead of using the alert name for this purpose. Alert names may occasionally be modified, while the **externalId** of each alert is permanent. For more information, see [Azure ATP SIEM log reference](cef-format-sa.md). 


## See Also

- [Working with sensitive accounts](sensitive-accounts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
