---
title: Download and schedule Microsoft Defender for Identity reports in Microsoft 365 Defender
description: Learn how to download and schedule Microsoft Defender for Identity reports from Microsoft 365 Defender.
ms.date: 06/21/2023
ms.topic: how-to
---

# Download and schedule Defender for Identity reports in Microsoft 365 Defender

Microsoft 365 Defender provides Defender for Identity reports, which you can either generate on demand or configure to be sent periodically by email.

## Access Defender for Identity reports in Microsoft 365 Defender

To access Defender for Identity reports in Microsoft 365 Defender, select **Settings > Identities > Report management**. 

Available reports include:

|Report name  |Description  |
|---------|---------|
|**Summary**| Presents a dashboard of your system status, including: <br><br>- **Summary**: A summary of detected network activity <br>- **Open suspicious activities**: Lists the suspicious activities you should take care of <br>- **Open health issues**: Lists Defender for Identity health issues you should take care of. <br><br> Suspicious activities and health issues are listed by type. |
|**Modification to sensitive groups**     |    Lists every time a modification is made to sensitive groups, such as admins, or manually tagged accounts or groups. <br><br>If you're using Defender for Identity standalone sensors, make sure that [events are forwarded from your domain controllers to the standalone sensors](configure-event-forwarding.md) in order to receive a full report about your sensitive groups.     |
|**Passwords exposed in cleartext**     | Lists all source computer and account passwords detected by Defender for Identity being sent in clear text. <br><br>**Note**: Some services use the LDAP non-secure protocol to send account credentials in plain text. This can even happen for sensitive accounts. Attackers monitoring network traffic can catch and then reuse these credentials for malicious purposes.     |
| **Lateral movement paths to sensitive accounts** | Lists the sensitive accounts that are exposed via lateral movement paths, for the selected report period. <br><br>For more information, see [Lateral movement paths](/defender-for-identity/classic-use-case-lateral-movement-path). |

## Generate a report on demand

To generate a report on demand:

1. In Microsoft 365 Defender, select **Settings > Identities** > **Report management**.

1. Select a report and then select **Download**.

1. In the download report pane that appears on the right, define a time period for your report and then select **Download Report**.

Your report is downloaded by your browser, where you can open or save it. 


## Schedule a report by email

To define a schedule for a report to be sent to you by email:

1. In Microsoft 365 Defender, select **Settings > Identities > Report management**.

1. Select a report and then select **Schedule report**.

1. Use the wizard to define the following details:

    1. On the **Set schedule** page, define the conditions in which you want to send the report, and the time you want it sent.

        Your report is sent according to your Microsoft 365 Defender time zone settings (*Local* or UTC). For more information, see [Set the time zone for Microsoft 365 Defender](/microsoft-365/security/defender/m365d-time-zone).

    1. On the **Recipients** page, enter and add email addresses for anyone you want to receive the report. Select **Next** to complete the scheduling.

    1. The **Finish** page shows a confirmation message. Select **Close** to close the wizard.
    
Once the scheduling is configured, repeat this procedure to edit the scheduled time or recipients.

### Remove all scheduled reports

To remove a scheduled report and stop it from being sent:


1. In Microsoft 365 Defender, select **Settings > Identities > Report management**.

1. Select the report you want to stop sending and then select **Reset schedule**.

1. In the confirmation message, select **Reset** to complete the process.


## Next steps

For more information, see:

- [Defender for Identity prerequisites](prerequisites.md)
- [Defender for Identity capacity planning](capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
