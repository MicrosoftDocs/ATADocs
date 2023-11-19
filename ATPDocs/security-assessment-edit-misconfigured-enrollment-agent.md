---
title: Edit misconfigured enrollment agent certificate template (ESC3) | Microsoft Defender for Identity
description: This article provides an overview of Microsoft Defender for Identity's misconfigured enrollment agent certificate template security posture assessment report.
ms.date: 01/29/2023
ms.topic: how-to
---

# Security assessment: Misconfigured enrollment agent certificate template (ESC3)  (Preview)

## What are misconfgured enrollment agent certificate templates?

Typically, users have an Enrollment Agent that enrolls their certificates for them. An Enrollment Agent certificate is a certificate with the *Certificate request agent* EKU in its EKU list, allowing it to enroll certificates for any eligible user by signing the CSR with the agent certificate.  While the setting is controllable, it defaults to allowing certificates for all eligible user.

If there is a published template with the *Certificate request agent* EKU that is enrollable by any user, without any mitigation enforced, an unprivileged user can enroll an Enrollment Agent certificate and use it afterwards for enrolling certificates.

While an Enrollment Agent certificate cannot enroll certificates for all templates, and some conditions must be met for an attacker to be able to take over the domain. The other template required for this specific abuse is any template that has EKU for authentication. It must be enrollable for any user, without requiring *Manager approval*, and with an appropriate schema version. There are default templates that meet these conditions.

If both required template configurations are found, an attacker with an unprivileged user can enroll an Enrollment Agent certificate and use it afterwards for enrolling certificates permitted for authentication on behalf of any arbitrary user. 

Microsoft Defender for Identity reports about Enrollment Agent certificate templates that endanger your organization only when both template types are found. Defender for Identity shows the Enrollment Agent templates on the **Exposed entities** pane.

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for misconfgured enrollment agent certificate templates.

1. Remediate the issues by performing at least one of the following steps:

    - Remove the *Certificate request agent* EKU.
    - Remove overly permissive enrollment permissions, which allow any user to enroll certificates based on that certificate template. Templates marked as vulnerable by Defender for Identity have at least one access list entry that allows enrollment for a built-in unprivileged group, such as *Authenticated Users* or *Everyone*, making this exploitable by any user.
    - Turn on the *CA certificate Manager approval* requirement.
    - Remove the certificate template from being published by any CA. Templates that aren't published cannot be requested, and therefore cannot be exploited.
    - Use Enrollment Agent restrictions on the Certificate Authority level. For example, you may want to restrict which users are allowed to act as an Enrollment Agent, and which templates can be requested.

Make sure to test your settings in a controlled environment before turning them on in production.

> [!NOTE]
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.


## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
