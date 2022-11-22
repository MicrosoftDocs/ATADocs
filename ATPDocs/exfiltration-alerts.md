---
title: Microsoft Defender for Identity exfiltration alerts 
description: This article explains the Microsoft Defender for Identity alerts issued when attacks typically part of exfiltration phase efforts are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Exfiltration alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](reconnaissance-alerts.md)
1. [Compromised credentials](compromised-credentials-alerts.md)
1. [Lateral Movements](lateral-movement-alerts.md)
1. [Domain dominance](domain-dominance-alerts.md)
1. **Exfiltration**

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Exfiltration** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network. In this article, you'll learn to understand, classify, prevent, and remediate the following attacks:

> [!div class="checklist"]
>
> - Data exfiltration over SMB (external ID 2030)
> - Suspicious communication over DNS (external ID 2031)


## See Also

- [Investigate a computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices)
- [Working with security alerts](/defender-for-identity/manage-security-alerts)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)