---
title: Do not expire passwords | Microsoft Defender for Identity
description: Learn about Microsoft Defender for Identity's `Do not expire passwords` security assessment in Microsoft Secure Score.
ms.date: 06/08/2023
ms.topic: how-to
---

# Security assessment: Do not expire passwords

> [!TIP]
> We highly recommend moving your organization to a password-less strategy. For more information, see [Password-less strategy - Windows Security | Microsoft Learn](/windows/security/identity-protection/hello-for-business/passwordless-strategy).
>

## Why is the 'Password never expires` attribute a risk?

Having the **Password never expires** attribute configured poses risks like weakened password security, increased exposure to credential theft, compliance and audit failures, and potential delays in incident response and recovery.

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for **Do not expire passwords**.

    For example:

    :::image type="content" source="media/secure-score/do-not-expire-passwords.png" alt-text="Screenshot of the Do not expire passwords security assessment." lightbox="media/secure-score/do-not-expire-passwords.png":::

1. Review the list of exposed entities that have the 'password never expire' attribute.

    - Entities include accounts that were previously authenticated using a password and currently have their password set to 'never expire'.

    - This report targets accounts that regularly authenticate using passwords. Password-less accounts are not listed in this report.


1. Take appropriate action on those entities by removing settings that are not secure.

To achieve the full score, remediate all exposed entities.

> [!NOTE]
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.


## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
