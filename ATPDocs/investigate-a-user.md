---
# required metadata

title: Azure ATP user investigation tutorial
d|Description: This article explains how to user Azure ATP security alerts to investigate a suspicious user.
keywords:
author: shsagir
ms.author: shsagir
ms.date: 09/15/2019
ms.topic: tutorial
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Tutorial: Investigate a user

> [!NOTE]
> The Azure ATP features explained on this page are also accessible using the new [portal](https://portal.cloudappsecurity.com).

Azure ATP alert evidence and lateral movement paths provide clear indications when users have performed suspicious activities or indications exist that their account has been compromised. In this tutorial you'll use the investigation suggestions to help determine the risk to your organization, decide how to remediate, and determine the best way to prevent similar future attacks.  

> [!div class="checklist"]
> * Gather information about the user.
> * Investigate activities that the user performed.
> * Investigate resources the user accessed.
> * Investigate lateral movement paths.

## Recommended investigation steps for suspicious users

Check and investigate the user profile for the following details and activities:

1. Who is the [user](entity-profiles.md)?
     1. Is the user a [sensitive user](sensitive-accounts.md) (such as admin, or on a watchlist, etc.)?  
     2. What is their role within the organization?
     3. Are they significant in the organizational tree?

2. Suspicious activities to [investigate](investigate-entity.md):
     1. Does the user have other opened alerts in Azure ATP, or in other security tools such as Windows Defender-ATP, Azure Security Center and/or Microsoft CAS?
     2. Did the user have failed log ons?
     3. Which resources did the user access?  
     4. Did the user access high value resources?  
     5. Was the user supposed to access the resources they accessed?  
     6. Which computers did the user log in to? 
     7. Was the user supposed to log in to those computers?
     8. Is there a [lateral movement path](use-case-lateral-movement-path.md) (LMP) between the user and a sensitive user?


## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](atp-reconnaissance-alerts.md)
- [Compromised credential alerts](atp-compromised-credentials-alerts.md)
- [Lateral movement alerts](atp-lateral-movement-alerts.md)
- [Domain dominance alerts](atp-domain-dominance-alerts.md)
- [Exfiltration alerts](atp-exfiltration-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
