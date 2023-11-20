---
title: Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1) | Microsoft Defender for Identity
description: This article provides an overview of Microsoft Defender for Identity's 'Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1)' identity security posture assessment report.
ms.date: 11/13/2023
ms.topic: how-to
---

# Security assessment: Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1)  (Preview)

## What are certificate requests for arbitrary users?

Each certificate is associated with an entity through its subject field. However, certificates also include a *Subject Alternative Name* (SAN) field, which allows the certificate to be valid for multiple entities.

The SAN field is commonly used for web services hosted on the same server, supporting the use of a single HTTPS certificate instead of separate certificates for each service. When the specific certificate is also valid for authentication, by containing an appropriate EKU, such as *Client Authentication*, it can be used to authenticate several different accounts.

If a certificate template has the *Supply in the request* option turned on, the template is vulnerable, and attackers may be able to enroll a certificate that's valid for arbitrary users.

> [!IMPORTANT]
> If the certificate is also permitted for authentication and there aren't any mitigation measures enforced, such as *Manager approval* or required authorized signatures, the certificate template is dangerous as it allows any unprivileged user to take over any arbitrary user, including a domain admin user.
>
> This specific setting is one of the most common misconfigurations.
> 

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for certificate requests for arbitrary users. For example:

    :::image type="content" source="media/secure-score/prevent-certificate-arbitrary-users.png" alt-text="Screenshot of the Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1) recommendation." lightbox="media/secure-score/prevent-certificate-arbitrary-users.png":::

1. To remediate certificate requests for arbitrary users, perform at least one of the following steps:

    - Turn off *Supply in the request* configuration.

    - Remove any EKUs that enable user authentication, such as *Client Authentication*, *Smartcard logon*, *PKINIT client authentication*, or *Any purpose*.

    - Remove overly permissive enrollment permissions, which allow any user to enroll certificate based on that certificate template.

        Certificate templates marked as vulnerable by Defender for Identity have at least one access list entry that supports enrollment for a built-in, unprivileged group, making this exploitable by any user. Examples of built-in, unprivileged groups include *Authenticated Users* or *Everyone*.

    - Turn on the CA certificate *Manager approval* requirement.

    - Remove the certificate template from being published by any CA. Templates that are not published cannot be requested, and therefore cannot be exploited.

Make sure to test your settings in a controlled environment before turning them on in production.

> [!NOTE]
> While this assessment is updated in near real time, scores and statuses are updated every 24 hours.  While the list of affected entities is updated within a few minutes of your implementing the recommendations, the status may still take time until it's marked as **Completed**.
>
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.
>

## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
