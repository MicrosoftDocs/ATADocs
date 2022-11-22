---
title: Microsoft Defender for Identity domain dominance security alerts
description: This article explains the Microsoft Defender for Identity alerts issued when attacks, typically part of domain dominance phase efforts, are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Domain dominance alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](reconnaissance-alerts.md)
1. [Compromised credentials](compromised-credentials-alerts.md)
1. [Lateral Movements](lateral-movement-alerts.md)
1. **Domain dominance**
1. [Exfiltration](exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Domain dominance** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network. In this article, you'll learn how to understand, classify, prevent, and remediate the following attacks:

> [!div class="checklist"]
>
> - Malicious request of Data Protection API master key (external ID 2020)
> - Remote code execution attempt (external ID 2019)
> - Suspected DCShadow attack (domain controller promotion) (external ID 2028)
> - Suspected DCShadow attack (domain controller replication request) (external ID 2029)
> - Suspected DCSync attack (replication of directory services) (external ID 2006)
> - Suspected Golden Ticket usage (encryption downgrade) (external ID 2009)
> - Suspected Golden Ticket usage (forged authorization data) (external ID 2013)
> - Suspected Golden Ticket usage (nonexistent account) (external ID 2027)
> - Suspected Golden Ticket usage (ticket anomaly) (external ID 2032)
> - Suspected Golden Ticket usage (ticket anomaly using RBCD) (external ID 2040)
> - Suspected Golden Ticket usage (time anomaly) (external ID 2022)
> - Suspected Skeleton Key attack (encryption downgrade) (external ID 2010)
> - Suspicious additions to sensitive groups (external ID 2024)
> - Suspicious service creation (external ID 2026)




> [!div class="nextstepaction"]
> [Exfiltration alerts](exfiltration-alerts.md)

## See Also

- [Investigate a computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices)
- [Working with security alerts](/defender-for-identity/manage-security-alerts)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)