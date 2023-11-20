---
title: Enforce encryption for RPC certificate enrollment interface (ESC8) | Microsoft Defender for Identity
description: This article provides an overview of Microsoft Defender for Identity's enforce encryption for RPC certificate enrollment security posture assessment report.
ms.date: 11/20/2023
ms.topic: how-to
---

# Security assessment: Enforce encryption for RPC certificate enrollment interface (ESC8)  (Preview)

## What is encryption with RPC certificate enrollment?

Active Directory Certificate Services (AD CS) supports certificate enrollment using the RPC protocol, specifically with the MS-ICPR interface. In such cases, the CA settings determine the security settings for the RPC interface, including the requirement for packet privacy.

If the `IF_ENFORCEENCRYPTICERTREQUEST` flag is turned on, the RPC interface only accepts connections with the `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` authentication level. This is the highest authentication level, and requires each packet to be signed and encrypted so as to prevent any kind of relay attack. This is similar to `SMB Signing` in the SMB protocol.

If the RPC enrollment interface does not require packet privacy, it becomes vulnerable to relay attacks (ESC8). The `IF_ENFORCEENCRYPTICERTREQUEST` flag is on by default, but is often turned off to allow clients that cannot support the required RPC authentication level, such as clients running Windows XP. 

## Prerequisites

This assessment is available only to customers who've installed a sensor on an AD CS server. For more information, see [New sensor type for Active Directory Certificate Services (AD CS)](whats-new.md#new-sensor-type-for-active-directory-certificate-services-ad-cs).

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for enforcing encryption for RPC certificate enrollment.  For example:

    :::image type="content" source="media/secure-score/enforce-encryption-rpc-certificate.png" alt-text="Screenshot of the Enforce encryption for RPC certificate enrollment interface (ESC8) recommendation." lightbox="media/secure-score/enforce-encryption-rpc-certificate.png":::

1. Research why the `IF_ENFORCEENCRYPTICERTREQUEST` flag is turned off.

1. Make sure to turn the `IF_ENFORCEENCRYPTICERTREQUEST` flag on to remove the vulnerability.

    To turn the flag on, run:

    ```cmd
    certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
    ```

    To restart the service, run:

    ```cmd
    net stop certsvc & net start certsvc
    ```

Make sure to test your settings in a controlled environment before turning them on in production.

> [!NOTE]
> While this assessment is updated in near real time, scores and statuses are updated every 24 hours.  While the list of affected entities is updated within a few minutes of your implementing the recommendations, the status may still take time until it's marked as **Completed**.
>
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.
>

## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
