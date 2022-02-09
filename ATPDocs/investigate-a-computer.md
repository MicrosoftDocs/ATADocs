---
title: Microsoft Defender for Identity computer investigation tutorial
description: This article explains how to use Microsoft Defender for Identity security alerts to investigate a suspicious computer.
ms.date: 10/26/2020
ms.topic: tutorial
---

# Tutorial: Investigate a computer

> [!NOTE]
> The experience described in this page can also be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender.

[!INCLUDE [Product long](includes/product-long.md)] alert evidence provides clear indications when computers have been involved in suspicious activities or when indications exist that a machine is compromised. In this tutorial you'll use the investigation suggestions to help determine the risk to your organization, decide how to remediate, and determine the best way to prevent similar attacks in the future.  

> [!div class="checklist"]
>
> - Check the computer for the logged in user.
> - Verify if the user normally accesses the computers.
> - Investigate suspicious activities from the computer.
> - Where there other alerts around the same time?

## Investigation steps for suspicious computers

To access the computer profile page, click on the specific computer mentioned in the alert that you wish to investigate. To assist your investigation, alert evidence lists all computers (and [users](investigate-a-user.md)) connected to each suspicious activity.

Check and investigate the computer profile for the following details and activities:

- What happened around the time of the suspicious activity?  
    1. Which [user](investigate-a-user.md) was logged in to the computer?
    1. Does that user normally log into or access the source or destination computer?
    1. Which resources where accessed? By which users?
      - If resources were accessed, were they high-value resources?
    1. Was the user supposed to access those resources?
    1. Did the [user](investigate-a-user.md) that accessed the computer perform other suspicious activities?

- Additional suspicious activities to investigate:
    1. Were other alerts opened around the same time as this alert in [!INCLUDE [Product short](includes/product-short.md)], or in other security tools such as Microsoft Defender for Endpoint, Azure Security Center and/or Microsoft CAS?
    1. Were there failed logons?

- If Microsoft Defender for Endpoint integration is enabled, click the Microsoft Defender for Endpoint badge to further investigate the computer. In Microsoft Defender for Endpoint you can see which processes and alerts occurred around the same time as the alert.
  - Were any new programs deployed or installed?

## Next steps

- [Investigate a user](investigate-a-user.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)

## Learn more

- Try our interactive guide: [Investigate and respond to attacks with Microsoft Defender for Identity](https://mslearn.cloudguides.com/guides/Investigate%20and%20respond%20to%20attacks%20with%20Microsoft%20Defender%20for%20Identity)
