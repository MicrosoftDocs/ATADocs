---
title: Working with the ATA Console
ms.custom: 
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology: 
  - security
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: 1bf264d9-9697-44b5-9533-e1c498da4f07
author: Rkarlin
---
# Working with the ATA Console
This section describes the ATA Console.

## Enable access to the ATA Console
Any user who is a member of the local Administrators group on the ATA Center server has permission to log in to the ATA Console and manage ATA settings. 
To allow a user to log in to the ATA Console without making them a local administrator, add them to the local group: **Microsoft Advanced Threat Analytics Administrators**.

## Logging into the ATA Console

-   In the ATA Center server, click the **Microsoft ATA Console**  icon on the desktop or open a browser and browse to the ATA Console.

    Alternatively, you can open a browser from either the ATA Center or the ATA Gateway and browse to the IP address you configured in the ATA Center installation for the ATA Console.

-   Enter your username and password and click **Log in**.

    You have to log in with a user who is a member of the local administrator group OR of the  Microsoft Advanced Threat Analytics Administrators group.

    ![](../Image/ATA_log_in_screen.jpg)

## ATA Console elements

-   **Attack time line**

    This is the default page you are taken to when you log in to the ATA Console. By default, all open suspicious activities are shown on the attack time line. You can filter the attack time line to show All, Open, Dismissed or Resolved suspicious activities. Suspicious activities are listed chronologically with the newest entries shown first in the list.

-   **Suspicious activity**

    When ATA detects a suspicious activity an entry is created in the attack time line. For more information, see [Working with Suspicious Activities](../Topic/Working_with_Suspicious_Activities.md).

-   **Notification bar**

    When a new suspicious activity is detected, the notification bar will open automatically on the right hand side. If there are new suspicious activities since the last time you logged in the notification bar will open after you have successfully logged in. To access it, you can click the arrow on the right at any time.

-   **Filtering**

    You can filter which suspicious activities are displayed in the attack time line or displayed in the entity profile suspicious activities tab based on Status and Severity.

-   **Search bar**

    On the top of the screen you will find a search bar. You can search for a specific user, computer or groups in ATA. To give it a try, just start typing.

    ![](../Image/ATA_console_search.png)

-   **Health Center**

    The Health Center provides you with alerts when something isn't working properly in your ATA network.

    Any time your system encounters a problem, such as a connectivity error or a disconnected ATA Gateway, the Health Center icon will let you know by displaying a red dot. ![](../Image/ATA_Health_Center_Alert_red_dot.png)

    Like suspicious activities, Health Center alerts can be dismissed or resolved and are categorized High, Medium or Low depending on their severity. If you resolve an alert that the ATA service detects as still active, it will automatically be moved to the Open list of alerts. If the system detects that there is no longer cause for an alert (the situation has been fixed), it will automatically be moved to the resolved list.

-   **Configuration**

    Modifying and viewing the ATA Configuration is accomplished by clicking the settings icon (three dots) on the menu bar, followed by Configuration.

    ![](../Image/ATA_config_icon.JPG)

-   **User and computer profiles**

    ATA builds a profile for each user and computer in the domain. In the user profile ATA will display general information about the user and will provide additional information on the following pages: Summary, Activities, and Suspicious activities.

    > [!NOTE]
    > A profile that ATA has not been able to fully resolve will be identified with half-filled circle icon next to it.![](../Image/ATA_Unresolved_Profile.jpg)

-   **Mini profile**

    Anywhere in the console where there is a single entity presented, such as a user or computer, if you hover you mouse over the entity a mini profile will automatically open displaying the following information if available:

    ![](../Image/ATA_mini_profile.jpg)

    -   Name

    -   Picture

    -   Email

    -   Telephone

    -   Number of suspicious activities by severity

## See Also
[For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)

