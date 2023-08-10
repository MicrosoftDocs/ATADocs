---
title: Classic portal - Working with Microsoft Defender for Identity Reports
description: Classic portal - Describes how you can generate reports in Microsoft Defender for Identity to monitor your network.
ms.date: 01/29/2023
ms.topic: conceptual
ROBOTS: NOINDEX
---

# Classic portal: Microsoft Defender for Identity Reports

[!INCLUDE [automatic-redirect](../includes/automatic-redirect.md)]

The Microsoft Defender for Identity reports section in the Defender for Identity portal enables you to schedule or immediately generate and download reports that provide you with system and entity status information. From the reports feature, you can create reports about system health, security alerts and potential lateral movement paths detected in your environment.

To access the reports page, click the report icon in the menu bar: ![report icon.](media/report-icon.png).
Available reports are:

- **Summary report**: The Summary report presents a dashboard of the status in the system. You can view three tabs - one for a **Summary** of what was detected on your network, **Open suspicious activities** that lists the suspicious activities you should take care of, and **Open health issues** that lists Defender for Identity health issues you should take care of. The suspicious activities listed are broken down by type, as are the health issues.

- **Modification of sensitive groups**: This report lists every time a modification is made to sensitive groups (such as admins, or manually tagged accounts or groups). If you're using Defender for Identity standalone sensors, in order to receive a full report about your sensitive groups, make sure that [events are forwarded from your domain controllers to the standalone sensors](deploy/configure-event-forwarding.md).

- **Passwords exposed in cleartext**: Some services use the LDAP non-secure protocol to send account credentials in plain text. This can even happen for sensitive accounts. Attackers monitoring network traffic can catch and then reuse these credentials for malicious purposes. This report lists all source computer and account passwords detected by Defender for Identity being sent in clear text.

- **Lateral movement paths to sensitive accounts**: This report lists the sensitive accounts that are exposed via lateral movement paths. For more information, see [Lateral movement paths](/defender-for-identity/classic-use-case-lateral-movement-path). This report collects potential lateral movement paths that were detected in the report period you select.

There are two ways to generate a report: either on demand or by scheduling a report to be sent to your email periodically.

To generate a report on demand:

1. In the Defender for Identity portal menu bar, click the report icon in the menu bar: ![report icon.](media/report-icon.png).

1. Under your selected report type, set the **From** and **To** dates and click **Download**.
 ![Screenshot showing report download.](media/reports.png)

To set a scheduled report:

1. In the **Reports** page, click **Set scheduled reports**, or in the Defender for Identity portal configuration page, under Notifications and Reports, click **Scheduled reports**.

    ![Schedule reports.](media/sched-reports.png)

    > [!NOTE]
    > By default, daily reports are designed to be sent shortly after midnight, UTC. Pick your own time by using the time selection option.

1. Click **Schedule** next to your selected report type, to set the frequency and email address for delivery of the reports. The report frequency you select determines the information included in the report. To add email addresses, click the plus sign next to the email address field, enter the address and click **Save**.

    ![Schedule report frequency and email.](media/sched-report1.png)

## Next steps

- [Defender for Identity prerequisites](deploy/prerequisites.md)
- [Defender for Identity capacity planning](deploy/capacity-planning.md)
- [Configure event collection](deploy/configure-event-collection.md)
- [Configuring Windows event forwarding](deploy/configure-event-forwarding.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
