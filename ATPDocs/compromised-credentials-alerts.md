---
title: Microsoft Defender for Identity compromised credentials phase security alerts
description: This article explains the Microsoft Defender for Identity alerts issued when attacks typical of the compromised credentials phase are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Compromised credential alerts

Typically, cyber-attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets – such as sensitive accounts, domain administrators, and highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](reconnaissance-alerts.md)
1. **Compromised credential**
1. [Lateral Movements](lateral-movement-alerts.md)
1. [Domain dominance](domain-dominance-alerts.md)
1. [Exfiltration](exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Compromised credential** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network. In this article, you'll learn how to understand, classify, remediate and prevent the following types of attacks:

> [!div class="checklist"]
>
> - [Suspicious modification of a sAMNameAccount attribute (CVE-2021-42278 and CVE-2021-42287 exploitation) (external ID 2419)](#suspicious-modification-of-a-samnameaccount-attribute-cve-2021-42278-and-cve-2021-42287-exploitation-external-id-2419)
> - [Honeytoken activity (external ID 2014)](#honeytoken-activity-external-id-2014)
> - [Suspected Brute Force attack (Kerberos, NTLM) (external ID 2023)](#suspected-brute-force-attack-kerberos-ntlm-external-id-2023)
> - [Suspected Brute Force attack (LDAP) (external ID 2004)](#suspected-brute-force-attack-ldap-external-id-2004)
> - [Suspected Brute Force attack (SMB) (external ID 2033)](#suspected-brute-force-attack-smb-external-id-2033)
> - [Suspected Kerberos SPN exposure (external ID 2410)](#suspected-kerberos-spn-exposure-external-id-2410)
> - [Suspected Netlogon privilege elevation attempt (CVE-2020-1472 exploitation) (external ID 2411)](#suspected-netlogon-priv-elev-2411)
> - [Suspected AS-REP Roasting attack (external ID 2412)](#suspected-as-rep-roasting-attack-external-id-2412)
> - [Suspected WannaCry ransomware attack (external ID 2035)](#suspected-wannacry-ransomware-attack-external-id-2035)
> - [Suspected use of Metasploit hacking framework (external ID 2034)](#suspected-use-of-metasploit-hacking-framework-external-id-2034)
> - [Suspicious VPN connection (external ID 2025)](#suspicious-vpn-connection-external-id-2025)



<a name="suspected-netlogon-priv-elev-2411"></a>




> [!div class="nextstepaction"]
> [Lateral Movement alerts](lateral-movement-alerts.md)

## See Also

- [Investigate a computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices)
- [Investigate a user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users)
- [Working with security alerts](/defender-for-identity/manage-security-alerts)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)