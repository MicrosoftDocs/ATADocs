---
# required metadata

title: Working with suspicious activities in Azure Advanced Threat Protection | Microsoft Docs
description: Describes how to review suspicious activities identified by Azure ATP
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/21/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: a06004bd-9f77-4e8e-a0e5-4727d6651a0f

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*



# Working with Suspicious Activities
This article explains the basics of how to work with Azure Advanced Threat Protection.

## Review suspicious activities on the attack time line
After logging in to the Azure ATP workspace portal, you are automatically taken to the open **Suspicious Activities Time Line**. Suspicious activities are listed in chronological order with the newest suspicious activities on the top of the time line.
Each suspicious activity has the following information:

-   Entities involved, including users, computers, servers, domain controllers, and resources.

-   Times and time frame of the suspicious activities.

-   Severity of the suspicious activity, High, Medium, or Low.

-   Status: Open, closed, or suppressed.

-   Ability to

    -   Share the suspicious activity with other people in your organization via email.

    -   Export the suspicious activity to Excel.

> [!NOTE]
> -   When you hover your mouse over a user or computer, an entity mini-profile is displayed that provides additional information about the entity and includes the number of suspicious activities that the entity is linked to.
> -   If you click on an entity, it takes you to the entity profile of the user or computer.

![Azure ATP suspicious activities timeline image](media/atp-sa-timeline.png)

## Filter suspicious activities list
To filter the suspicious activities list:

1.  In the **Filter by** pane on the left side of the screen, select one of the following options: **All**, **Open**, **Closed**, or **Suppressed**.

2.  To further filter the list, select **High**, **Medium**, or **Low**.

**Suspicious activity severity**

-   **Low**

    Indicates suspicious activities that can lead to attacks designed for malicious users or software to gain access to organizational data.

-   **Medium**

    Indicates suspicious activities that can put specific identities at risk for more severe attacks that could result in identity theft or privileged escalation

-   **High**

    Indicates suspicious activities that can lead to identity theft, privilege escalation, or other high-impact attacks




## Managing suspicious activities
You can change the status of a suspicious activity by clicking the current status of the suspicious activity and selecting one of the following **Open**, **Suppressed**, **Closed**, or **Deleted**.
To do this, click the three dots at the top right corner of a specific suspicious activity to reveal the list of available actions.

![Azure ATP Actions for suspicious activities](./media/atp-sa-actions.png)

**Suspicious activity status**

-   **Open**: All new suspicious activities appear in this list.

-   **Close**: Is used to track suspicious activities that you identified, researched, and fixed for mitigated.

    > [!NOTE]
    > If the same activity is detected again within a short period of time, Azure ATP may reopen a closed activity.

-   **Suppress**: Suppressing an activity means you want to ignore it for now, and only be alerted again if there's a new instance. This means that if there's a similar alert Azure ATP doesn't reopen it. But if the alert stops for seven days, and is then seen again, you are alerted again.

- **Delete**: If you Delete an alert, it is deleted from the system, from the database and you will NOT be able to restore it. After you click delete, you'll be able to delete all suspicious activities of the same type.

- **Exclude**: The ability to exclude an entity from raising more of a certain type of alerts. For example, you can set Azure ATP to exclude a specific entity (user or computer) from alerting again for a certain type of suspicious activity, such as a specific admin who runs remote code or a security scanner that does DNS reconnaissance. In addition to being able to add exclusions directly on the Suspicious activity as it is detected in the time line, you can also go to the Configuration page to **Exclusions**, and for each suspicious activity you can manually add and remove excluded entities or subnets (for example for Pass-the-Ticket). 

> [!NOTE]
> The configuration pages can only be modified by Azure ATP admins.


## See Also

- [Working with the Azure ATP workspace portal](atp-workspaces.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)