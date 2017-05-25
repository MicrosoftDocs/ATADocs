---
# required metadata

title: Monitor Advanced Threat Analytics Health Center alerts | Microsoft Docs
description: Use the ATA Health Center to check how the ATA service is working and be alerted to potential problems.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 05/23/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: d6c783b2-46c5-4211-b21a-d6b17f08d03d

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Advanced Threat Analytics version 1.7*


# Working with ATA system health and events

## ATA Health Center
The ATA Health Center lets you know how your ATA service is performing and alerts you to problems.

## Working with the ATA Health Center
The ATA Health Center lets you know that there's a problem by raising an alert (a red dot) above the Health Center icon in the menu bar.

![ATA Health Center red dot toolbar](media/ATA-Health-Center-Alert-red-dot.png)

### Managing ATA health
To check up on your system's overall health, click the Health Center icon in the menu bar ![ATA Health Center icon](media/ATA-red-dot.png)

-   All open alerts can be managed by setting them to **Resolved** or **Dismissed**. In the Alert, click **Open** and scroll down to either **Resolved** or **Dismissed**.

-   If you resolve an issue and ATA detects that the issue persists, the issue will automatically be moved back to the **Open** issues list. If ATA detects that an open issue is resolved, it will automatically be moved to the **Resolved** issues list.

-   **Dismissed** issues are issues that you do not want ATA to continue to check - for example, if you are alerted to an issue that you know exists and you do not plan to resolve the issue but do not want to continue to get notifications about it and you no longer want to see it in your **Open** issues list, you can set it to **Dismissed**.

![ATA Health Center issues image](media/ATA-Health-Issue.JPG)

## Event logging

You can view ATA events in the Windows Event Log viewer, under Microsoft ATA. 
- For the ATA Center you can see a list of Suspicious activities and Health Issues, as well as Audit log events that detail every change made in the system, and every log in by a user. For example, if someone deletes a Suspicious Activity or suppresses it, it will show up as an event in the log. 
- For the ATA Gateway, the event log contains an audit trail in the log of changes to the ATA Gateway configuration, for example if someone updates the certificate.




## See Also
- [Working with ATA detection settings](working-with-detection-settings.md)
- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
