---
title: Microsoft Defender for Identity unsecure domain configuration assessments
description: This article provides an overview of Microsoft Defender for Identity's entities with unsecure domain configurations identity security posture assessment report.
ms.date: 05/30/2022
ms.topic: how-to
---

# Security assessment: Unsecure domain configurations

## What are unsecure domain configurations?

Microsoft Defender for Identity continuously monitors your environment to identify domains with configurations values that expose a security risk, and reports on these domains to assist you in protecting your environment.

## What risk do unsecure domain configurations pose?

Organizations that fail to secure their domain configurations leave the door unlocked for malicious actors.

Malicious actors, much like thieves, often look for the easiest and quietest way into any environment. Domains configured with unsecure configurations are windows of opportunity for attackers and can expose risks.

## How do I use this security assessment?

1. Review the suggested improvement action at <https://security.microsoft.com/securescore?viewid=actions> to discover which of your domains have unsecure configurations.
    ![Review top impacted entities and create an action plan.](media/unsecure-domain-configurations.png)
1. Take appropriate action on these domains by modifying or removing the relevant configurations.

> [!NOTE]
>
> - This assessment is updated in near real time.

## Remediation

Use the remediation appropriate to the relevant configurations as described in the following table.

| Recommended action | Remediation | Reason |
| --- | --- | --- |
| **Set ms-DS-MachineAccountQuota to "0"**             | Set the [MS-DS-Machine-Account-Quota](/windows/win32/adschema/a-ms-ds-machineaccountquota) attribute to "0". | Limiting the ability of non-privileged users to register devices in the domain. For more information about this particular property and how it affects device registration, see [Default limit to number of workstations a user can join to the domain](/troubleshoot/windows-server/identity/default-workstation-numbers-join-domain). |

## See Also

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
