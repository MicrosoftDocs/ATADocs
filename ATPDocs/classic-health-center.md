---
title: Classic portal - Monitor Microsoft Defender for Identity System Health and Events
description: Classic portal - Use the health center to check how the Microsoft Defender for Identity service is working and be alerted to potential problems and view system events in the Event viewer.
ms.date: 01/30/2023
ms.topic: how-to
ROBOTS: NOINDEX
---

# Classic portal: Work with Microsoft Defender for Identity health and events

[!INCLUDE [automatic-redirect](../includes/automatic-redirect.md)]

## Microsoft Defender for Identity health center

The Microsoft Defender for Identity health center lets you know how your Defender for Identity instance is performing and alerts you when there are problems.

## Working with the Defender for Identity health center

The Defender for Identity health center lets you know that there's a problem by raising an alert (a red dot) above the Health Center icon in the navigation bar.

![Defender for Identity health center red dot toolbar](media/health-bar.png)

### Managing Defender for Identity health

To check up on the overall health of your Defender for Identity instance, select **Health** ![Defender for Identity health center icon](media/red-dot.png)

- All open issues can be managed by setting them to **Close**,  or **Suppress**, by clicking the three dots in the corner of the alert and making your selection.

- **Open**: All new suspicious activities appear in this list.

- **Close**: Is used to track suspicious activities that you identified, researched, and fixed for mitigated.

    > [!NOTE]
    > Defender for Identity may reopen a closed activity if the same activity is detected again within a short period of time.

- **Suppress**: Suppressing an activity means you want to ignore it for now, and only be alerted again if there's a new instance. If there's a similar alert Defender for Identity doesn't reopen it. But if the alert stops for seven days, and is then seen again, you're alerted again.

- **Reopen**: You can reopen a closed or suppressed alert so that it appears as **Open** in the timeline again.

- **Delete**: From within the security alert timeline, you also have the option to delete a health issue. If you Delete an alert, it is deleted from the instance and you will NOT be able to restore it. After you click delete, you'll be able to delete all security alerts of the same type.

![Defender for Identity health center issues image](media/health-issue.png)

## See Also

- [Working with suspicious activities](/defender-for-identity/manage-security-alerts)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
