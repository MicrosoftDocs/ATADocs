---
title: Microsoft Defender for Identity riskiest lateral movement paths assessments
description: This article provides an overview of Microsoft Defender for Identity's sensitive entities with the riskiest lateral movement paths identity security posture assessment report.
ms.date: 10/26/2020
ms.topic: how-to
---

# Security assessment: Riskiest lateral movement paths (LMP)

## What are Risky lateral movement paths?

[!INCLUDE [Product long](includes/product-long.md)] continuously monitors your environment to identify **sensitive** accounts with the riskiest lateral movement paths that expose a security risk, and reports on these accounts to assist you in managing your environment. Paths are considered risky if they have three or more non-sensitive accounts that can expose the **sensitive** account to credential theft by malicious actors.

Learn more about LMP:

- [[!INCLUDE [Product short](includes/product-short.md)] Lateral Movement Paths (LMPs)](use-case-lateral-movement-path.md)
- [MITRE ATT&CK Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

## What risk do risky lateral movement paths pose?

Organizations that fail to secure their **sensitive** accounts leave the door unlocked for malicious actors.

Malicious actors, much like thieves, often look for the easiest and quietest way into any environment. Sensitive accounts with risky lateral movement paths are windows of opportunities for attackers and can expose risks.

For example, the riskiest paths are more readily visible to attackers and, if compromised, can give an attacker access to your organization's most sensitive entities.

## How do I use this security assessment?

1. Use the report table to discover which of your **sensitive** accounts have risky LMPs.
    ![Review top impacted entities and create an action plan.](media/cas-isp-riskiest-lmp-1.png)
1. Take appropriate action:
    - Remove the entity from the group as specified in the recommendation.
    - Remove the local administrator permissions for the entity from the device specified in the recommendation.

    > [!NOTE]
    > Wait 24 hours and then check that the recommendation no longer appears in the list.

> [!NOTE]
> This assessment is updated every 24 hours.

## See Also

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
