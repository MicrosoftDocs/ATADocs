---
# required metadata

title: Investigating lateral movement path attacks with Azure ATP | Microsoft Docs
description: This article describes how to detect lateral movement path attacks with Azure Advanced Threat Protection (ATP).
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 6/14/2018
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


Lateral movement is when an attacker uses non-sensitive accounts to gain access to sensitive accounts. This behavior can be done using the methods described in the [Suspicious activity guide](suspicious-activity-guide.md). To understand who the administrators are in your network and which machines the attacker can accessed, the attacker can take advantage of the data on the domain controllers.

Azure ATP enables you to take preemptive action on your network to prevent attackers from succeeding at lateral movement.

## Discovery your at-risk sensitive accounts

To discover which sensitive accounts in your network were vulnerable because of their connection to non-sensitive accounts or resources, in a specific timeframe, follow these steps. 

1. In the Azure ATP workspace portal menu, click the reports icon ![reports icon](./media/atp-report-icon.png).

2. Under **Lateral movements paths to sensitive accounts**, if there are no lateral movement paths found, the report is grayed out. If there are lateral movement paths, then the dates of the report automatically select the first date when there is relevant data. The lateral movement path report provides data for the last 60 days.

 ![reports](./media/reports.png)

3. Click **Download**.

3. The Excel file that is created provides you with details about your sensitive accounts that are at risk. The **Summary** tab provides graphs that detail the number of sensitive accounts, computers, and averages for at-risk resources. The **Details** tab provides a list of the sensitive accounts that you should be concerned about. Note that the paths may not be available today because they were detected previously.


## Investigate



1. In the Azure ATP workspace portal, search for the Lateral movement badge that's added to the entity profile when the entity is in a lateral movement path ![lateral icon](./media/lateral-movement-icon.png) or ![path icon](./media/paths-icon.png). Note that this is available if there was lateral movement within the last two days. 

2. In the user profile page that opens, click the **Lateral movement paths** tab. 

3. The graph that is displayed provides a map of the possible paths to the sensitive user. The graph shows connections that have been made over the last two days, so the exposure is fresh. If activity is not detected for the last two days.

4. Review the graph to see what you can learn about exposure of your sensitive user's credentials. For example, in this map, you can follow the **Logged into by** gray arrows to see where Samira logged in with their privileged credentials. In this case, Samira's sensitive credentials were saved on the computer REDMOND-WA-DEV. Then, see which other users logged into which computers that created the most exposure and vulnerability. You can see this by looking at the **Administrator on** black arrows to see who has admin privileges on the resource. In this example, everyone in the group Contoso All has the ability to access user credentials from that resource.  

 ![user profile lateral movement paths](media/user-profile-lateral-movement-paths.png)


## Preventative best practices

- The best way to prevent lateral movement is to make sure that sensitive users use their administrator credentials only when logging into hardened computers. In the example, make sure that if the admin Samira needs access to REDMOND-WA-DEV, she logs in with a username and password other than their admin credentials.

- It is also recommended that you make sure that no one has unnecessary administrative permissions. In the example, you should check if everyone in Contoso All really needs admin rights on REDMOND-WA-DEV.

- Make sure people only have access to necessary resources. In the example, Oscar Posada significantly widens Samira's exposure. Is it necessary that the user be included in the group **Contoso All**? Are there subgroups that you could create to minimize exposure?

**Tip** – If activity is not detected over the last two days, the graph does not appear, but the lateral movement path report will still be available to provide you with information about lateral movement paths over the last 60 days.

**Tip** - For instructions on how to set your servers to allow Azure ATP to perform the SAM-R operations needed for lateral movement path detection, [configure SAM-R](install-atp-step8-samr.md).


## See Also

- [Configure SAM-R required permissions](install-atp-step8-samr.md)
- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)