---
title: Remove access rights on suspicious accounts with the Admin SDHolder permission | Microsoft Defender for Identity
description: Learn about Microsoft Defender for Identity's `Remove access rights on suspicious accounts with the Admin SDHolder permission` security assessment in Microsoft Secure Score.
ms.date: 06/08/2023
ms.topic: how-to
---

# Security assessment: Remove access rights on suspicious accounts with the Admin SDHolder permission

This article describes the **Remove access rights on suspicious accounts with the Admin SDHolder permission** security assessment, which highlights risky access rights on suspicious accounts.

## Why might the Admin SDHolder permission be risky?

Having non-sensitive accounts with **Admin SDHolder** (security descriptor holder) permissions can have significant security implications, including:

- Leading to unauthorized privilege escalation, where attackers can exploit these accounts to gain administrative access and compromise sensitive systems or data
- Increasing the attack surface, making it harder to track and mitigate security incidents, potentially exposing the organization to greater risks.

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for **Remove access rights on suspicious accounts with the Admin SDHolder permission**.

    For example:

    :::image type="content" source="media/secure-score/remove-suspicious-access-rights.png" alt-text="Screenshot of the Admin SDHolder security assessment." lightbox="media/secure-score/remove-suspicious-access-rights.png":::

1. Review the list of exposed entities to discover which of your non-sensitive accounts have the **Admin SDHolder** permission.

1. Take appropriate action on those entities by removing their privileged access rights.
 
To achieve the full score, remediate all exposed entities.

> [!NOTE]
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.


## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
