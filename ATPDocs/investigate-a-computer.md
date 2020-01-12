---
# required metadata

title: Azure ATP computer investigation tutorial | Microsoft Docs
d|Description: This article explains how to use Azure ATP security alerts to investigate a suspicious computer.
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


# Tutorial: Investigate a computer

> [!NOTE]
> The Azure ATP features explained on this page are also accessible using the new [portal](https://portal.cloudappsecurity.com).

Azure ATP alert evidence provides clear indications when computers have been involved in suspicious activities or when indications exist that a machine is compromised. In this tutorial you'll use the investigation suggestions to help determine the risk to your organization, decide how to remediate, and determine the best way to prevent similar attacks in the future.  

> [!div class="checklist"]
> * Check the computer for the logged in user.
> * Verify if the user normally accesses the computers.
> * Investigate suspicious activities from the computer.
> * Where there other alerts around the same time?


## Investigation steps for suspicious computers

To access the computer profile page, click on the specific computer mentioned in the alert that you wish to investigate. To assist your investigation, alert evidence lists all computers (and [users](investigate-a-user.md)) connected to each suspicious activity.

Check and investigate the computer profile for the following details and activities:

- What happened around the time of the suspicious activity?  
  1. Which [user](investigate-a-user.md) was logged in to the computer?
  2. Does that user normally log into or access the source or destination computer?
  3. Which resources where accessed? By which users?
      - If resources were accessed, were they high value resources?
  4. Was the user supposed to access those resources?
  5. Did the [user](investigate-a-user.md) that accessed the computer perform other suspicious activities?

- Additional suspicious activities to investigate:
    1. Were other alerts opened around the same time as this alert in Azure ATP, or in other security tools such as Windows Defender ATP, Azure Security Center and/or Microsoft CAS?
    2. Were there failed logons?


- If Windows Defender ATP integration is enabled, click the Windows Defender ATP badge to further investigate the computer. In Windows Defender ATP you can see which processes and alerts occurred around the same time as the alert.
    1. Were any new programs deployed or installed?

## Next steps

- [Investigate a user](investigate-a-user.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](atp-reconnaissance-alerts.md)
- [Compromised credential alerts](atp-compromised-credentials-alerts.md)
- [Lateral movement alerts](atp-lateral-movement-alerts.md)
- [Domain dominance alerts](atp-domain-dominance-alerts.md)
- [Exfiltration alerts](atp-exfiltration-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
