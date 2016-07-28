---
# required metadata

title: Setting ATA Notifications | Microsoft ATA
description: Describes how to have ATA notify you (by email or by ATA event forwarding) when it detects suspicious activities 
keywords:
author: rkarlin
manager: mbaldwin
ms.date: 04/28/2016
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
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

## Provide ATA with up your email server settings
ATA can notify you when it detects a suspicious activity. For ATA to be able to send email notifications, you must first configure the **Email server settings**.

1.  On the ATA Center server, click the **Microsoft Advanced Threat Analytics Management** icon on the desktop.

2.  Enter your user name and password and click **Log in**.

3.  Select the settings option on the toolbar and select **Configuration**.

    ![ATA configuration settings icon](media/ATA-config-icon.JPG)

4.  In the **General** tab, under **Email server**, enter the following information:

    |Field|Description|Value|
    |---------|---------------|---------|
    |SMTP server endpoint (required)|Enter the FQDN of your SMTP server.|For example:<br />smtp.contoso.com|
    |SSL|Toggle SSL if the SMTP server required SSL. **Note:** If you enable SSL you will also need to change the Port number.|Default is disabled|
    |Authentication|Enable if your SMTP server requires authentication. **Note:** If you enable authentication you must provide a user name and password of an email account that has permission to connect to the SMTP server.|Default is disabled|
    |Send from (required)|Enter an email address from whom the email will be sent from.|For example:<br />ATA@contoso.com|
    ![ATA email server settings image](media/ATA-email-server.png)

## Provide ATA with your Syslog server settings
ATA can notify you when it detects a suspicious activity by sending the notification to your Syslog server. If you enable Syslog notifications, you can set the following for them.

1.  Before configuring Syslog notifications, work with your SIEM admin to find out the following information:

    -   FQDN or IP address of the SIEM server

    -   Port on which the SIEM server is listening

    -   What transport to use: UDP, TCP or TLS (Secured Syslog)

    -   Format in which to send the data RFC 3164 or 5424

2.  On the ATA Center server, click the **Microsoft Advanced Threat Analytics Management** icon on the desktop.

3.  Enter your user name and password and click **Log in**.

4.  Select the settings option on the toolbar and select **Configuration**.

    ![ATA configuration settings icon](media/ATA-config-icon.JPG)

5.  Select **Syslog server** and enter the following information:

    |Field|Description|
    |---------|---------------|
    |Syslog server endpoint|FQDN of the Syslog server|
    |Transport|Can be UDC, TCP or TLS (Secured Syslog)|
    |Format|This is the format that ATA uses to send events to the SIEM server - either RFC 5424 or RFC 3164.|





## See Also
[Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
