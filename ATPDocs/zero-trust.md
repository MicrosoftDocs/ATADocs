---
title: Zero Trust with Microsoft Defender for Identity
description: Explains how Microsoft Defender for Identity fits into an overall Zero Trust strategy when deploying Microsoft 365 Defender.
ms.date: 02/21/2023
ms.topic: conceptual
ms.collection:
  -       zerotrust-services
---


# Zero Trust with Defender for Identity

[Zero Trust](/security/zero-trust/zero-trust-overview) is a security strategy for designing and implementing the following sets of security principles:

|Verify explicitly  |Use least privilege access  |Assume breach  |
|---------|---------|---------|
|Always authenticate and authorize based on all available data points.     | Limit user access with Just-In-Time and Just-Enough-Access (JIT/JEA), risk-based adaptive policies, and data protection.        | Minimize blast radius and segment access. Verify end-to-end encryption and use analytics to get visibility, drive threat detection, and improve defenses.        |

Defender for Identity is a primary component of a Zero Trust strategy and your XDR deployment with Microsoft 365 Defender. Defender for Identity uses Active Directory signals to detect sudden account changes like privilege escalation or high-risk lateral movement, and reports on easily exploited identity issues like unconstrained Kerberos delegation, for correction by the security team.

## Monitoring for Zero Trust

When monitoring for Zero Trust, make sure review and mitigate open alerts from Defender for Identity together with your other security operations. You may also want to integrate Defender for Identity with Microsoft Defender for Cloud Apps to bring on-premises signals into any specific user's overall risk calculation.

For example, integrating with Defender for Identity alerts Azure AD if users are indulging in risky behavior while accessing on-premises, non-modern resources like File Shares. This behavior can then be factored into the overall user risk, and may require that you block the user from further access in the cloud.

> [!TIP]
> Ingest your alerts into [Microsoft Sentinel](/azure/sentinel/overview), a cloud-native, security information event management (SIEM) and security orchestration automated response (SOAR) solution to provide your Security Operations Center (SOC) with a single pane of glass for monitoring security events across your enterprise.
>

## Next steps

For more information, see the [Zero Trust Guidance Center](/security/zero-trust).