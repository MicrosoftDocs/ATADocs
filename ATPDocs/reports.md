---
title: Microsoft Defender for Identity reports in Microsoft 365 Defender
description: Learn how to generate Microsoft Defender for Identity reports from Microsoft 365 Defender.
ms.date: 06/11/2023
ms.topic: how-to
---

# Microsoft Defender for Identity reports in Microsoft 365 Defender

The Microsoft 365 Defender **Reports** page includes Defender for Identity reports with system and entity status details. Use these templates to create your own reports about system health, security alerts, and potential lateral movement paths detected in your environment.

Either generate a report on demand, or configure Microsoft 365 Defender to send you a report periodically by email.

## Access Defender for Identity reports in Microsoft 365 Defender

To access Defender for Identity reports in Microsoft 365 Defender, select **Reports > Identities > Reports management**.

Available reports include:

|Report name  |Description  |
|---------|---------|
|**Summary**| Presents a dashboard of your system status, including: <br><br>- **Summary**: A summary of detected network activity <br>- **Open suspicious activities**: Lists the suspicious activities you should take care of <br>- **Open health issues**: Lists Defender for Identity health issues you should take care of. <br><br> Suspicious activities and health issues are listed by type. |
|**Modification to sensitive groups**     |    Lists every time a modification is made to sensitive groups, such as admins, or manually tagged accounts or groups. If you're using Defender for Identity standalone sensors, make sure that [events are forwarded from your domain controllers to the standalone sensors](configure-event-forwarding.md) in order to receive a full report about your sensitive groups.     |
|**Passwords exposed in cleartext**     | Lists all source computer and account passwords detected by Defender for Identity being sent in clear text. <br><br>**Note**: Some services use the LDAP non-secure protocol to send account credentials in plain text. This can even happen for sensitive accounts. Attackers monitoring network traffic can catch and then reuse these credentials for malicious purposes.     |
| **Lateral movement paths to sensitive accounts** | Lists the sensitive accounts that are exposed via lateral movement paths, for the selected report perid. For more information, see [Lateral movement paths](/defender-for-identity/classic-use-case-lateral-movement-path). |

## Generate a report on demand

To generate a report on demand:

1. In Microsoft 365 Defender, select **Settings > Identities**, and then select one or more reports. <!--unclear how to get here?-->/
1. Select **Download** and define the time period for your report.
1. Select **Download report** to start generating and downloading your report.

## Schedule a report by email

To define a schedule for a report to be sent to you by email:

1. In Microsoft 365 Defender, select **Settings > Identities > Edit schedule**. If this is the first time you're scheduling a report, select **Configure schedule**.
1. Use the wizard to define the following details:

    - **Data time range**: Define the time period for your scheduled report
    - **Recipients**: Enter the email addresses for anyone you want to receive your report
    - **Set schedule**: Define when you want the report to be sent

    > [!NOTE]
    > By default, daily reports are designed to be sent shortly after midnight, UTC. Pick your own time by using the time selection option.

1. At the end of the wizard, in the **Finish** page, select **Close** to close the wizard.

### Remove a scheduled report

To remove a scheduled report and stop it from being sent:

1. In Microsoft 365 Defender, select **Settings > Identities**, and select the report you want to stop sending.
1. Select **Reset schedule > Reset** to stop sending the selected report.


## Next steps

For more information, see:

- [Defender for Identity prerequisites](prerequisites.md)
- [Defender for Identity capacity planning](capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
