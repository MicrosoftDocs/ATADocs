---
# required metadata

title: Setting syslog settings in Azure Advanced Threat Protection | Microsoft Docs
description: Describes how to have Azure ATP notify you (by email or by Azure ATP event forwarding) when it detects suspicious activities 
keywords:
author: mlottner
ms.author: mlottner
manager: barbkess
ms.date: 12/02/2018
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

Azure ATP can notify you when it detects suspicious activities and issues security alerts as well as health alerts by sending the notification to your Syslog server. If you enable Syslog notifications, you can set the following:

1. Before configuring Syslog notifications, work with your SIEM admin to find out the following information:

   -   FQDN or IP address of the SIEM server

   -   Port on which the SIEM server is listening

   -   What transport to use: UDP, TCP, or TLS (Secured Syslog)

   -   Format in which to send the data RFC 3164 or 5424

2. Enter the instance URL.

3. Enter your Azure Active Directory user name and password and click **Log in**.

4. Select the settings option on the toolbar and select **Configuration**.

   ![Azure ATP configuration settings icon](media/ATP-config-menu.png)

5. Click **Notifications**, and then, under **Syslog notifications** click **Configure** and enter the following information:

   |Field|Description|
   |---------|---------------|
   |sensor|Select a designated sensor to be responsible for aggregating all the Syslog events and forwarding them to your SIEM server.|
   |Service endpoint|FQDN of the Syslog server and optionally change the port number (default 514)|
   |Transport|Can be UDP, TCP, or TLS (Secured Syslog)|
   |Format|This is the format that Azure ATP uses to send events to the SIEM server - either RFC 5424 or RFC 3164.|

   ![Azure ATP Syslog server settings image](media/atp-syslog.png)

6. You can select which events to send to your Syslog server. Under **Syslog notifications**, specify which notifications should be sent to your Syslog server - new security alerts, updated security alerts, and new health issues.

> [!NOTE]
> If you plan to create automation or scripts for Azure ATP SIEM logs, we recommend using the **externalId** field to identify the alert type instead of using the alert name for this purpose. Alert names may occasionally be modified, while the **externalId** of each alert is permanent. For more information, see [Azure ATP SIEM log reference](cef-format-sa.md). 


## See Also

- [Working with sensitive accounts](sensitive-accounts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
