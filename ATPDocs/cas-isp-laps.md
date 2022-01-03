---

title: Microsoft Defender for Identity Microsoft LAPS usage assessments
description: This article provides an overview of Microsoft Defender for Identity's Microsoft LAPS usage identity security posture assessment report.
ms.date: 01/03/2022
ms.topic: how-to
---

# Security assessment: Microsoft LAPS usage

## What is Microsoft LAPS?

Microsoft's "Local Administrator Password Solution" (LAPS) provides management of local administrator account passwords for domain-joined computers. Passwords are randomized and stored in Active Directory (AD), protected by ACLs, so only eligible users can read it or request its reset.

## What risk does not implementing LAPS pose to an organization?

LAPS provide a solution to the issue of using a common local account with an identical password on every computer in a domain. LAPS resolve this issue by setting a different, rotated random password for the common local administrator account on every computer in the domain.

LAPS simplifies password management while helping customers implement additional recommended defenses against cyberattacks. In particular, the solution mitigates the risk of lateral escalation that results when customers use the same administrative local account and password combination on their computers. LAPS stores the password for each computer's local administrator account in AD, secured in a confidential attribute in the computer's corresponding AD object. The computer can update its own password data in AD, and domain administrators can grant read access to authorized users or groups, such as workstation helpdesk administrators.

## How do I use this security assessment?

1. Use the report table to discover which of your domains have some (or all) compatible Windows devices that are not protected by LAPS, or that have not had their LAPS managed password changed in the last 60 days.
1. For domains that are partially protected, select the relevant row to view the list of devices not protected by LAPS in that domain.
    ![Select domain with LAPS devices.](media/cas-isp-laps-1.png)
1. Take appropriate action on those devices by downloading, installing and configuring or troubleshooting [Microsoft LAPS](https://go.microsoft.com/fwlink/?linkid=2104282) using the documentation provided in the download.
    ![Remediate LAPS device.](media/cas-isp-laps-2.png)

> [!NOTE]
> This assessment is updated every 24 hours.

## See Also

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
