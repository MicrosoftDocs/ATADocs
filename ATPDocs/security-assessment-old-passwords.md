---
title: Manage accounts with passwords more than 180 days old | Microsoft Defender for Identity
description: Learn about Microsoft Defender for Identity's `Manage accounts with passwords more than 180 days old` security assessment in Microsoft Secure Score.
ms.date: 06/08/2023
ms.topic: how-to
---

# Security assessment: Manage accounts with passwords more than 180 days old

This article describes the **Manage accounts with passwords more than 180 days old**, which highlights accounts at risk because of older passwords.

> [!TIP]
> We highly recommend moving your organization to a password-less strategy. For more information, see [Password-less strategy - Windows Security | Microsoft Learn](/windows/security/identity-protection/hello-for-business/passwordless-strategy).
>

## Why are passwords that are older than 180 days a risk?

Passwords more than 180 days old increase vulnerability to password attacks and heighten the risk of credential theft. These passwords may also lead to non-compliance with security standards, reduce accountability and user awareness, and impede incident response efforts in case of a security breach.

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for **Manage accounts with passwords more than 180 days old**.

    For example:

    :::image type="content" source="media/secure-score/old-passwords.png" alt-text="Screenshot of the Manage accounts with passwords more than 180 days old security assessment." lightbox="media/secure-score/old-passwords.png":::

1. Review this list of exposed entities to discover which of your accounts have a password more than 180 days old.

    This report targets accounts that regularly authenticate using passwords. Password-less accounts are not listed in this report.

1. Take appropriate action on those entities either by making them change their password or restricting their access to sensitive resources.

To achieve the full score, remediate all exposed entities.

> [!NOTE]
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.

## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
