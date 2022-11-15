---
title: Microsoft Defender for Identity discovery security alerts
description: This article explains Microsoft Defender for Identity alerts issued when discovery attacks are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Discovery alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. **Reconnaissance**
1. [Compromised credentials](compromised-credentials-alerts.md)
1. [Lateral Movements](lateral-movement-alerts.md)
1. [Domain dominance](domain-dominance-alerts.md)
1. [Exfiltration](exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Reconnaissance** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network.

In this article, you'll learn how to understand, classify, remediate, and prevent the following types of attacks:

> [!div class="checklist"]
>
> - Account enumeration reconnaissance (external ID 2003)
> - Active Directory attributes reconnaissance (LDAP) (external ID 2210)
> - Network mapping reconnaissance (DNS) (external ID 2007)
> - Security principal reconnaissance (LDAP) (external ID 2038)
> - User and Group membership reconnaissance (SAMR) (external ID 2021)
> - User and IP address reconnaissance (SMB) (external ID 2012)



## See Also

- [Investigate a computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices)
- [Investigate a user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users)
- [Working with security alerts](/defender-for-identity/manage-security-alerts)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [[!INCLUDE [Product short](includes/product-short.md)] SIEM log reference](cef-format-sa.md)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)