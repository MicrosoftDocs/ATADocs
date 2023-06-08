---
title: Enable security features like Enhanced Protection for Authentication (EPA) for your domains | Microsoft Defender for Identity
description: Learn about Microsoft Defender for Identity's `Enable security features for your domains` security assessment in Microsoft Secure Score.
ms.date: 06/08/2023
ms.topic: how-to
---

# Security assessment: Enable security features like Enhanced Protection for Authentication (EPA) for your domains

## Why is not enabling EPA considered a risk?

Not enabling Enhanced Protection for Authentication (EPA) on domain controllers increases the vulnerability to credential theft attacks, compromising the security of authentication processes and potentially exposing sensitive credentials to unauthorized access.

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for **Enable security features like Enhanced Protection for Authentication (EPA) for your domains**.

<!--missing image
    For example:
-->

1. Review this list of domain controllers to discover which of your domain controllers has security features turned off.

1. Take appropriate action on those domains by turning on EPA. 

To achieve the full score, you must remediate all exposed entities.

> [!NOTE]
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.


## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Learn more about EPA](https://msrc-blog.microsoft.com/2009/12/08/extended-protection-for-authentication/)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
