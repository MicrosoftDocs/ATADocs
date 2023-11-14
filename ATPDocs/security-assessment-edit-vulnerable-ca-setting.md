---
title: Edit vulnerable Certificate Authority setting | Microsoft Defender for Identity
description: This article provides an overview of Microsoft Defender for Identity's vulnerable Certificate Authority setting report.
ms.date: 11/14/2023
ms.topic: how-to
---

# Security assessment: Edit vulnerable Certificate Authority setting

## What are vulnerable Certificate Authority settings?

Unprivileged users that can specify the users in the Subject Alternative Names (SAN) settings can lead to immediate compromise, and post a great risk to your organization.

If the AD CS `editflags` > `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is turned on, each user can specify the SAN settings for their certificate request. This, in turn affects all certificate templates, whether they have the `Supply in the request` option turned on or not.

If there is a template where the `EDITF_ATTRIBUTESUBJECTALTNAME2` setting is turned on, and the template is valid for authentication, an attacker can enroll a certificate that can impersonate any arbitrary account.

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for editing vulnerable Certificate Authority settings.

<!--image tbd-->

1. Research why this setting is turned on.

1. Turn the setting off by running:

    ```cmd
    certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
    ```

1. Restart the service by running:

    ```cmd
    net stop certsvc & net start certsvc
    ```

Make sure to test your settings in a controlled environment before turning them on in production.

> [!NOTE]
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.


## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
