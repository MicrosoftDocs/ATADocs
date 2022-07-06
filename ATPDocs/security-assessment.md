---
title: Microsoft Defender for Identity's security posture assessments
description: This article provides an overview of Microsoft Defender for Identity's identity security posture assessment reports.
ms.date: 06/23/2022
ms.topic: how-to
---

# Microsoft Defender for Identity's security posture assessments

Typically, organizations of all sizes have limited visibility into whether or not their on-premises apps and services could introduce a security vulnerability to their organization. The problem of limited visibility is especially true regarding use of unsupported or outdated components.

While your company may invest significant time and effort on hardening identities and identity infrastructure (such as Active Directory, Active Directory Connect) as an on-going project, it's easy to remain unaware of common misconfigurations and use of legacy components that represent one of the greatest threat risks to your organization. Microsoft security research reveals that most identity attacks utilize common misconfigurations in Active Directory and continued use of legacy components (such as NTLMv1 protocol) to compromise identities and successfully breach your organization. To combat this effectively, [!INCLUDE [Product long](includes/product-long.md)] now offers proactive identity security posture assessments to detect and suggest improvement actions across your on-premises Active Directory configurations.

## What do Defender for Identity's security posture assessments provide?

- Detections and contextual data on known exploitable components and misconfigurations, along with relevant paths for remediation.
- [!INCLUDE [Product short](includes/product-short.md)] detects not only suspicious activities, but also actively monitors your on-premises identities and identity infrastructure for weak spots, using the existing [!INCLUDE [Product short](includes/product-short.md)] sensor.
- Accurate assessment reports of your current organization security posture, enabling quick response and effect monitoring in a continuous cycle.

## How do I get started?

### Access

[!INCLUDE [Product short](includes/product-short.md)] security assessments are available using the [Microsoft Secure Score dashboard](/microsoft-365/security/defender/microsoft-secure-score). The assessments are available in the **Identity** category in Microsoft Secure Score.

### What is Microsoft Secure Score?

Microsoft Secure Score is a measurement of an organization's security posture, with a higher number indicating more improvement actions taken. It can be found at <https://security.microsoft.com/securescore> in the [Microsoft 365 Defender portal](/microsoft-365/security/defender/microsoft-365-defender).

### Licensing

A [!INCLUDE [Product short](includes/product-short.md)] license is required.

### Identity security posture assessments

[!INCLUDE [Product short](includes/product-short.md)] offers the following identity security posture assessments. Each assessment is a downloadable report with instructions for use and tools for building an action plan to remediate or resolve.

### Assessment reports

- [Domain controllers with Print Spooler service available](cas-isp-print-spooler.md)
- [Dormant entities in sensitive groups](cas-isp-dormant-entities.md)
- [Entities exposing credentials in clear text](cas-isp-clear-text.md)
- [Microsoft LAPS usage](cas-isp-laps.md)
- [Legacy protocols usage](cas-isp-legacy-protocols.md)
- [Riskiest lateral movement paths (LMP)](cas-isp-riskiest-lmp.md)
- [Unmonitored domain controllers](cas-isp-unmonitored-domain-controller.md)
- [Unsecure account attributes](cas-isp-unsecure-account-attributes.md)
- [Unsecure Kerberos delegation](cas-isp-unconstrained-kerberos.md)
- [Unsecure SID History attributes](cas-isp-unsecure-sid-history-attribute.md)
- [Weak cipher usage](cas-isp-weak-cipher.md)

To access identity security posture assessments:

1. Open the [Microsoft Secure Score dashboard](https://security.microsoft.com/securescore).
1. Select the **Improvement actions** tab. You can search for a particular improvement action, or filter the results (for example, by the category **Identity**).

    ![Improvement actions.](media/improvement-actions.png)

1. For more details about the assessment, select the **Improvement action**.

    ![Select the assessment.](media/select-assessment.png)

## Next steps

- [Learn more about Microsoft Secure Score](/microsoft-365/security/defender/microsoft-secure-score)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
