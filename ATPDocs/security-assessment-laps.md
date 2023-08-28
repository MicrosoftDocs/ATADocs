---

title: Microsoft LAPS usage assessment  | Microsoft Defender for Identity
description: This article describes Microsoft Defender for Identity's Microsoft LAPS usage identity security posture assessment report.
ms.date: 08/28/2023
ms.topic: how-to
#CustomerIntent: As a Defender for Identity user, I want to understand the Microsoft LAPS usage security assessment so that I can be sure that I'm mitigating relevant risks appropriately.
---

# Security assessment: Microsoft LAPS usage

This article describes the **Microsoft LAPS usage** security assessment, available with Microsoft Defender for Identity, from [Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score).

## Prerequisites

To use the **Microsoft LAPS usage** security assessment, you'll need:

- [Defender for Identity deployed](deploy-defender-identity.md)
- Access to [Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)

## What is Microsoft LAPS?

Microsoft's Local Administrator Password Solution (LAPS) provides management of local administrator account passwords for domain-joined computers. Passwords are randomized and stored in Active Directory (AD), protected by ACLs, so only eligible users can read it or request its reset.

This security assessment supports [legacy Microsoft LAPS](https://www.microsoft.com/en-us/download/details.aspx?id=46899) only.

## What risk does not implementing LAPS pose to an organization?

LAPS provide a solution to the issue of using a common local account with an identical password on every computer in a domain. LAPS resolve this issue by setting a different, rotated random password for the common local administrator account on every computer in the domain.

LAPS simplifies password management while helping customers implement additional recommended defenses against cyberattacks. In particular, the solution mitigates the risk of lateral escalation that results when customers use the same administrative local account and password combination on their computers. LAPS stores the password for each computer's local administrator account in AD, secured in a confidential attribute in the computer's corresponding AD object. The computer can update its own password data in AD, and domain administrators can grant read access to authorized users or groups, such as workstation helpdesk administrators.

## How do I use this security assessment?

To use the **Microsoft LAPS usage** security assessment:

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> to discover which of your domains have some (or all) compatible Windows devices that aren't protected by LAPS, or that haven't had their LAPS managed password changed in the last 60 days.

    ![See which domains have devices unprotected by LAPS.](media/cas-isp-laps-1.png)

1. For domains that are partially protected, select the relevant row to view the list of devices not protected by LAPS in that domain.

    ![Select domain with devices unprotected by LAPS.](media/cas-isp-laps-2.png)

    > [!NOTE]
    > If the entire domain is not protected with LAPS, you won't see the list of all the unprotected devices.

1. Take appropriate action on those devices by downloading, installing and configuring or troubleshooting [Microsoft LAPS](https://go.microsoft.com/fwlink/?linkid=2104282) using the documentation provided in the download.

    ![Remediate devices unprotected by LAPS.](media/laps-unprotected-devices.png)

> [!NOTE]
> This assessment is updated every 24 hours.

## Related content

For more information, see [Microsoft Secure Score documentation](/microsoft-365/security/defender/microsoft-secure-score).