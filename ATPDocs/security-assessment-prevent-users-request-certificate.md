---
title: Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1) | Microsoft Defender for Identity
description: This article provides an overview of Microsoft Defender for Identity's 'Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1)' identity security posture assessment report.
ms.date: 11/13/2023
ms.topic: how-to
---

# Security assessment: Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1)

## What are certificate requests for arbitrary users?

Each certificate is associated with an entity through its subject field. However, a certificate also includes a *Subject Alternative Name* (SAN) field, which allows the certificate to be valid for multiple entities. 

The SAN field is commonly used for web services hosted on the same server, supporting the use of a single HTTPS certificate instead of separate certificates for each service. When the specific certificate is also valid for authentication, by containing an appropriate EKU, such as Client Authentication, it can be used to authenticate several different accounts.

Users enroll a certificate that is valid for additional accounts by selecting the *Supply in the request* option for a certificate template, and then stating in the CSR which entities are included in the certificate SAN. In this case, any user with sufficient enrollment permissions can enroll a certificate valid for arbitrary users.

If the certificate is permitted for authentication and no mitigation measures, such as *Manager approval* and required authorized signatures, are enforced, the certificate template is dangerous, and allows any unprivileged user to take over any arbitrary user, including a domain admin user.


## How do I use this security assessment to improve my organizational security posture?

Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for certificate requests for arbitrary users.

<!--IMAGE TBD-->

> [!NOTE]
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.

## Remediation

> [!NOTE]
> Make sure to test the following settings in a controlled environment before enabling them in production.

To remediate certificate requests for arbitrary users, perform at least one of the following steps:

- Turn off *Supply in the request* configuration.

- Remove any EKUs that enable user authentication, such as Client Authentication, Smartcard logon, PKINIT client authentication, or Any purpose.

- Remove overly permissive enrollment permissions, which allows any user to enroll certificate based on that certificate template.

    Certificate templates marked as vulnerable by Defender for Identity have at least one access list entry that supports enrollment for a built-in unprivileged group, such as *Authenticated Users* or *Everyone*, making this exploitable by any user.

- Turn on the CA certificate *Manager approval* requirement.

- Remove the certificate template from being published by any CA. Templates that are not published cannot be requested, and therefore cannot be exploited.


## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
