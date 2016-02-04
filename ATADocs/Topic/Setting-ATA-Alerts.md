---
title: Setting ATA Alerts
ms.custom: 
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology: 
  - security
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: 14cb7513-5dc8-49cb-b3e0-94f469c443dd
author: Rkarlin
---
# Setting ATA Alerts
ATA can alert you when it detects a suspicious activity, either by email or by using ATA event forwarding and forwarding the event to your SIEM/syslog server. If you enable either or both of these types of alerts, you can set the following for them.

> [!NOTE]
> -   Email notifications include a link that will take the user directly to the suspicious activity that was detected. The host name portion of the link is taken from the setting of the ATA Console URL on the ATA Center page. By default, the ATA Console URL is the IP address selected during the installation of the ATA Center.  If you are going to configure email alerts it is recommended to use an FQDN as the ATA Console URL.
> -   System Health Alert alerts are only sent via email.
> -   Alerts are sent from the ATA Center to either the SMTP server and the Syslog server.
> -   Email alerts for suspicious activities are only sent when the suspicious activity is created.

## Setting language and frequency
The **Language** setting applies to notifications sent by email and notifications sent to the Syslog server.

The **Frequency** setting applies only to notifications sent to the Syslog server.

1.  Open the ATA Console.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![](../Image/ATA-config-icon.JPG)

3.  Select **Alerts**.

4.  Under **Language**, select the language of your choice.

5.  Under **Frequency**, select **Low frequency** if you want to receive a brief notification only when a new alert is generated. Select **High frequency** if you want to receive a detailed notification when a new alert is generated as well as when existing alerts are modified.

    ![](../Image/ATA-alerts-verbosity-language.png)

6.  Click **Save**.

## Setting up email alerts
ATA can alert you when it detects a suspicious activity. If you enable email alerts, you can set the following for them.

1.  On the ATA Center server, click the **Microsoft Advanced Threat Analytics Management** icon on the desktop.

2.  Enter your user name and password and click **Log in**.

3.  Select the settings option on the toolbar and select **Configuration**.

    ![](../Image/ATA-config-icon.JPG)

4.  Select **Alerts**.

5.  Turn on **Mail** to enable email alerts and enter the following information:

    |Field|Description|Value|
    |---------|---------------|---------|
    |SMTP server endpoint (required)|Enter the FQDN of your SMTP server.|For example:<br />smtp.contoso.com|
    |SSL|Toggle SSL if the SMTP server required SSL. **Note:** If you enable SSL you will also need to change the Port number.|Default is disabled|
    |Authentication|Enable if your SMTP server requires authentication. **Note:** If you enable authentication you must provide a user name and password of an email account that has permission to connect to the SMTP server.|Default is disabled|
    |Send from (required)|Enter an email address from whom the email will be sent from.|For example:<br />ATA@contoso.com|
    |Send to (required)|Enter the email addresses of the users or email groups that should get emails when ATA detects a suspicious activity. **Note:** Enter one email address at a time and click the plus sign to add it.|For example:<br />securityteam@contoso.com|

## Setting up ATA event forwarding to SIEM
ATA can alert you when it detects a suspicious activity by sending the alert to your Syslog server. If you enable Syslog alerts, you can set the following for them.

1.  Before configuring Syslog alerts, Work with your SIEM admin to find out the following information:

    -   FQDN or IP address of the SIEM server

    -   Port on which the SIEM server is listening

    -   What transport to use UDP or TCP or Secured TCP

    -   Format in which to send the data RFC 3164 or 5424

2.  On the ATA Center server, click the **Microsoft Advanced Threat Analytics Management** icon on the desktop.

3.  Enter your user name and password and click **Log in**.

4.  Select the settings option on the toolbar and select **Configuration**.

    ![](../Image/ATA-config-icon.JPG)

5.  Select **Alerts**.

6.  Turn on **Syslog** to enable alerts about suspicious activities  to be sent to your Syslog server, and enter the following information:

    |Field|Description|
    |---------|---------------|
    |Syslog server endpoint|FQDN of the Syslog server|
    |Transport|Can be UDC, TCP or Secure TCP|
    |Format|This is the format that ATA uses to send events to the SIEM server - either RFC 5424 or RFC 3164.|

## See Also
[For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)

