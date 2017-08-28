---
# required metadata

title: Monitor Advanced Threat Analytics System Health and Events | Microsoft Docs
description: Use the ATA Health Center to check how the ATA service is working and be alerted to potential problems and view system events in the Event viewer.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 08/28/2017
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

*Applies to: Advanced Threat Analytics version 1.8*


# Working with ATA system health and events

## ATA Health Center
The ATA Health Center lets you know how your ATA service is performing and alerts you to problems.

## Working with the ATA Health Center
The ATA Health Center lets you know that there's a problem by raising an alert (a red dot) above the Health Center icon in the menu bar.

![ATA Health Center red dot toolbar](media/ATA-Health-Center-Alert-red-dot.png)

### Managing ATA health
To check up on your system's overall health, click the Health Center icon in the menu bar ![ATA Health Center icon](media/ATA-red-dot.png)

-   All open alerts can be managed by setting them to **Close**, **Suppress**, or **Delete** by clicking the three dots in the corner of the alert and making your selection.

-   **Open**: All new suspicious activities appear in this list.

-   **Close**: Is used to track suspicious activities which you identified, researched and fixed for mitigated.

    > [!NOTE]
    > ATA may reopen a resolved activity if it the same activity is detected again within a short period of time.

-   **Suppress**: Suppressing an activity means you want to ignore it for now, and only be alerted again if there's a new instance. This means that if there's a similar alert ATA won't reopen it. But if the alert stops for 7 days, and is then seen again, you will be alerted again.

- **Delete**: If you Delete an alert, it will be deleted from the system, from the database and you will NOT be able to restore it. After you click delete, you'll be able to delete all suspicious activities of the same type.



![ATA Health Center issues image](media/ATA-Health-Issue.JPG)






## See Also

- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
