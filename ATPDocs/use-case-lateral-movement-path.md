---
# required metadata

title: Investigating lateral movement path attacks with Azure ATP | Microsoft Docs
description: This article describes how to detect lateral movement path attacks with Azure Advanced Threat Protection (ATP).
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 7/25/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: de15c920-8904-4124-8bdc-03abd9f667cf

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection version 1.9*

# Investigating lateral movement paths with Azure ATP


Lateral movement is when an attacker uses non-sensitive accounts to gain access to sensitive accounts. This can be done using the methods described in the [Suspicious activity guide](suspicious-activity-guide.md). Lateral movement is used by attackers to identify and gain access to the sensitive accounts and machines in your network using non-sensitive accounts that share resources. Once an attacker has gained access to sensitive accounts and machines, the attacker can also take advantage of the data on your domain controllers.


## Discovery your at-risk sensitive accounts

To discover which sensitive accounts in your network are exposed because of their connection to non-sensitive accounts or resources, follow these steps. 

1. In the Azure ATP workspace portal menu, click the reports icon ![reports icon](./media/atp-report-icon.png).

2. Under **Lateral movements paths to sensitive accounts**, if there are no potential lateral movement paths found, the report is grayed out. If there are potential lateral movement paths, the report automatically pre-selects the first date when there is relevant data. The lateral movement path report provides data for up to 60 days.

 ![reports](./media/reports.png)

3. Click **Download**.

4. An Excel file is created that provides you with details about your potential lateral movement paths and sensitive account exposure for the dates selected. The **Summary** tab provides graphs that detail the number of sensitive accounts, computers, and averages for at-risk resources. The **Details** tab provides a list of the sensitive accounts that you should investigate further. Note that the paths detailed in the report may no longer be available because they were detected previously.


## Investigate



1. In the Azure ATP workspace portal, search for the Lateral movement badge that's added to the entity profile when the entity is in a lateral movement path ![lateral icon](./media/lateral-movement-icon.png) or ![path icon](./media/paths-icon.png). Note that badges will only appear if there was lateral movement within the last 48 hours. 

2. In the user profile page that opens, click the **Lateral movement paths** tab. 

3. The graph that is displayed provides a map of the possible paths to the sensitive user. The graph shows the possible connections observed in the last 48 hours. If no activity was detected in the last two days, the graph will not appear. 

4. Review the graph to see what you can learn about exposure of your sensitive user's credentials. For example, in this map, you can follow the **Logged into by** gray arrows to see where Samira logged in with their privileged credentials. In this case, Samira's sensitive credentials were saved on the REDMOND-WA-DEV computer. Now, notice which other users logged into which computers that created the most exposure and vulnerability. You can see this by looking at the **Administrator on** black arrows to see who has admin privileges on the resource. In this example, everyone in the group Contoso All has the ability to access user credentials from that resource.  

 ![user profile lateral movement paths](media/user-profile-lateral-movement-paths.png)


## Preventative best practices

- The best way to prevent lateral movement is to make sure that sensitive users use their administrator credentials only when logging into hardened computers. In the example, make sure that if Samira the admin needs access to REDMOND-WA-DEV, they log in with a username and password other than their admin credentials.

- It is also recommended that you make sure that no one has unnecessary administrative permissions. In the example, you should check if everyone in Contoso All actually requires admin rights on REDMOND-WA-DEV.

- Make sure people only have access to necessary resources. In the example, Oscar Posada significantly widens Samira's exposure. Is it necessary that this user be included in the group **Contoso All**? Are there subgroups that could be created to minimize exposure?

**Tip** – When no activity is detected during the past 48 hours and the graph is unavailable, the lateral movement path report is still available and provides you with information about potential lateral movement paths detected over the last 60 days. 

**Tip** - For instructions on how to set your clients and servers to allow Azure ATP to perform the SAM-R operations needed for lateral movement path detection, see [configure SAM-R](install-atp-step8-samr.md).


## See Also

- [Configure SAM-R required permissions](install-atp-step8-samr.md)
- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)