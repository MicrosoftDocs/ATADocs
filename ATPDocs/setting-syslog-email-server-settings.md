---
# required metadata

title: Setting email notification settings in Azure Threat Protection | Microsoft Docs
description: Describes how to have ATP notify you (by email or by ATP event forwarding) when it detects suspicious activities 
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: a2d29c9c-7ecb-4804-b74b-fde899b28648

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Threat Protection*



# Provide ATP with your email server settings
ATP can notify you when it detects a suspicious activity. For ATP to be able to send email notifications, you must first configure the **Email server settings**.

1.  On the Azure ATP cloud service server, click the **Microsoft Azure Threat Protection Management** icon on the desktop.

2.  Enter your user name and password and click **Log in**.

3.  Select the settings option on the toolbar and select **Configuration**.

    ![ATP configuration settings icon](media/ATP-config-icon.png)

4.  In the **notifications** section, under **Mail server**, enter the following information:

    |Field|Description|Value|
    |---------|---------------|---------|
    |SMTP server endpoint (required)|Enter the FQDN of your SMTP server and optionally change the port number (default 25).|For example:<br />smtp.contoso.com|
    |SSL|Toggle SSL if the SMTP server required SSL. **Note:** If you enable SSL, you also need to change the Port number.|Default is disabled|
    |Authentication|Enable if your SMTP server requires authentication. **Note:** If you enable authentication, you must provide a user name and password of an email account that has permission to connect to the SMTP server.|Default is disabled|
    |Send from (required)|Enter an email address from whom the email will be sent from.|For example:<br />ATP@contoso.com|
    ![ATP email server settings image](media/ata-email-server.png)

## Provide ATP with your Syslog server settings
ATP can notify you when it detects a suspicious activity by sending the notification to your Syslog server. If you enable Syslog notifications, you can set the following for them.

1.  Before configuring Syslog notifications, work with your SIEM admin to find out the following information:

    -   FQDN or IP address of the SIEM server

    -   Port on which the SIEM server is listening

    -   What transport to use: UDP, TCP, or TLS (Secured Syslog)

    -   Format in which to send the data RFC 3164 or 5424

2.  On the Azure ATP cloud service server, click the **Microsoft Azure Threat Protection Management** icon on the desktop.

3.  Enter your user name and password and click **Log in**.

4.  Select the settings option on the toolbar and select **Configuration**.

    ![ATP configuration settings icon](media/ATP-config-menu.png)

5.  Under Notifications section, Select **Syslog server** and enter the following information:

    |Field|Description|
    |---------|---------------|
    |Syslog server endpoint|FQDN of the Syslog server and optionally change the port number (default 514)|
    |Transport|Can be UDP, TCP, or TLS (Secured Syslog)|
    |Format|This is the format that ATP uses to send events to the SIEM server - either RFC 5424 or RFC 3164.|

 ![ATP Syslog server settings image](media/atp-syslog.png)



## See Also
[Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
