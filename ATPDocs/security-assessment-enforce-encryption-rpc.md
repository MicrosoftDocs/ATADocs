---
title: Enforce encryption for RPC certificate enrollment interface (ESC8) | Microsoft Defender for Identity
description: This article provides an overview of Microsoft Defender for Identity's enforce encryption for RPC certificate enrollment security posture assessment report.
ms.date: 11/14/2023
ms.topic: how-to
---

# Security assessment: Enforce encryption for RPC certificate enrollment interface (ESC8)  (Preview)

## What is encryption with RPC certificate enrollment?

Active Directory Certificate Services (AD CS) supports certificate enrollment using the RPC protocol, specifically with the MS-ICPR interface.

In such cases, the CA settings determine the security settings for the RPC interface, including the requirement for packet privacy.

If the `IF_ENFORCEENCRYPTICERTREQUEST` flag is turned on, the RPC interface only accepts connections with the `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` authentication level. This is the highest authentication level, and requires each packet to be signed and encrypted, preventing any kind of relay attack, similar to `SMB Signing` in the SMB protocol.

If the RPC enrollment interface does not require packet privacy, it becomes vulnerable to relay attacks (ESC8). The `IF_ENFORCEENCRYPTICERTREQUEST` flag is on by default, but is often turned off to allow clients that cannot support the required RPC authentication level, such as clients running Windows XP. 

## How do I use this security assessment to improve my organizational security posture?

1. Review the recommended action at <https://security.microsoft.com/securescore?viewid=actions> for enforcing encryption for RPC certificate enrollment.

<!--image tbd-->

1. Research why the `IF_ENFORCEENCRYPTICERTREQUEST` flag is turned off.

1. Make sure to turn the `IF_ENFORCEENCRYPTICERTREQUEST` flag on to remove the vulnerability.

    Make sure to test the following settings in a controlled environment before enabling them in production, and then make sure to update any affected clients if there are any. 

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
> This assessment is updated in near real time.
> The reports show the affected entities from the last 30 days. After that time, entities no longer affected will be removed from the exposed entities list.

## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
