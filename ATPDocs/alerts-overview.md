---
title: Microsoft Defender for Identity security alert guide
description: This article provides a list of the security alerts issued by Microsoft Defender for Identity.
ms.date: 03/22/2022
ms.topic: conceptual
---

# Microsoft Defender for Identity Security Alerts

> [!NOTE]
> The experience described in this page can be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender.

[!INCLUDE [Product long](includes/product-long.md)] security alerts explain the suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] sensors on your network, and the actors and computers involved in each threat. Alert evidence lists contain direct links to the involved users and computers, to help make your investigations easy and direct.

[!INCLUDE [Product short](includes/product-short.md)] security alerts are divided into the following categories or phases, like the phases seen in a typical cyber-attack kill chain. Learn more about each phase, the alerts designed to detect each attack, and how to use the alerts to help protect your network using the following links:

1. [Reconnaissance phase alerts](reconnaissance-alerts.md)
1. [Compromised credential phase alerts](compromised-credentials-alerts.md)
1. [Lateral movement phase alerts](lateral-movement-alerts.md)
1. [Domain dominance phase alerts](domain-dominance-alerts.md)
1. [Exfiltration phase alerts](exfiltration-alerts.md)

To learn more about the structure and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md).

## Security alert name mapping and unique external IDs

The following table lists the mapping between alert names, their corresponding unique external IDs, their severity, and their MITRE ATT&CK Matrix&trade; tactic. When used with scripts or automation, Microsoft recommends use of alert external IDs in place of alert names, as only security alert external IDs are permanent, and not subject to change.

### External IDs

| Security  alert name                                         | Unique  external ID | Severity                                                 | MITRE  ATT&CK Matrix™                                        |
| ------------------------------------------------------------ | ------------------- | -------------------------------------------------------- | ------------------------------------------------------------ |
| Suspected   overpass-the-hash attack (Kerberos)              | 2002                | Medium                                                   | Lateral movement                                             |
| Account   enumeration reconnaissance                         | 2003                | Medium                                                   | Discovery                                                    |
| Suspected   Brute Force attack (LDAP)                        | 2004                | Medium                                                   | Credential access                                            |
| Suspected   DCSync attack (replication of directory services) | 2006                | High                                                     | Credential access, Persistence                               |
| Network   mapping reconnaissance (DNS)                       | 2007                | Medium                                                   | Discovery                                                    |
| Suspected   Golden Ticket usage (encryption downgrade)       | 2009                | Medium                                                   | Persistence, Privilege Escalation, Lateral movement          |
| Suspected   Skeleton Key attack (encryption downgrade)       | 2010                | Medium                                                   | Persistence, Lateral movement                                |
| User   and IP address reconnaissance (SMB)                   | 2012                | Medium                                                   | Discovery                                                    |
| Suspected   Golden Ticket usage (forged authorization data)  | 2013                | High                                                     | Credential access                                            |
| Honeytoken   activity                                        | 2014                | Medium                                                   | Credential access, Discovery                                 |
| Suspected   identity theft (pass-the-hash)                   | 2017                | High                                                     | Lateral movement                                             |
| Suspected   identity theft (pass-the-ticket)                 | 2018                | High or Medium                                           | Lateral movement                                             |
| Remote   code execution attempt                              | 2019                | Medium                                                   | Execution,  Persistence, Privilege escalation, Defense evasion, Lateral movement |
| Malicious   request of Data Protection API master key        | 2020                | High                                                     | Credential access                                            |
| User   and Group membership reconnaissance (SAMR)            | 2021                | Medium                                                   | Discovery                                                    |
| Suspected   Golden Ticket usage (time anomaly)               | 2022                | High                                                     | Persistence, Privilege Escalation, Lateral movement          |
| Suspected   Brute Force attack (Kerberos, NTLM)              | 2023                | Medium                                                   | Credential access                                            |
| Suspicious   additions to sensitive groups                   | 2024                | Medium                                                   | Persistence, Credential access,                              |
| Suspicious   VPN connection                                  | 2025                | Medium                                                   | Defense evasion, Persistence                                 |
| Suspicious   service creation                                | 2026                | Medium                                                   | Execution,  Persistence, Privilege Escalation, Defense evasion, Lateral movement |
| Suspected   Golden Ticket usage (nonexistent account)        | 2027                | High                                                     | Persistence, Privilege Escalation, Lateral movement          |
| Suspected   DCShadow attack (domain controller promotion)    | 2028                | High                                                     | Defense evasion                                              |
| Suspected   DCShadow attack (domain controller replication request) | 2029                | High                                                     | Defense evasion                                              |
| Data   exfiltration over SMB                                 | 2030                | High                                                     | Exfiltration, Lateral movement, Command and control          |
| Suspicious   communication over DNS                          | 2031                | Medium                                                   | Exfiltration                                                 |
| Suspected   Golden Ticket usage (ticket anomaly)             | 2032                | High                                                     | Persistence, Privilege Escalation, Lateral movement          |
| Suspected   Brute Force attack (SMB)                         | 2033                | Medium                                                   | Lateral movement                                             |
| Suspected   use of Metasploit hacking framework              | 2034                | Medium                                                   | Lateral movement                                             |
| Suspected   WannaCry ransomware attack                       | 2035                | Medium                                                   | Lateral movement                                             |
| Remote code execution over DNS                               | 2036                | Medium                                                   | Lateral movement, Privilege escalation                       |
| Suspected   NTLM relay attack                                | 2037                | Medium or Low if observed  using signed NTLM v2 protocol | Lateral  movement, Privilege escalation                      |
| Security   principal reconnaissance (LDAP)                   | 2038                | Medium                                                   | Credential access                                            |
| Suspected   NTLM authentication tampering                    | 2039                | Medium                                                   | Lateral  movement, Privilege escalation                      |
| Suspected   Golden Ticket usage (ticket anomaly using RBCD)  | 2040                | High                                                     | Persistence                                                  |
| Suspected   rogue Kerberos certificate usage                 | 2047                | High                                                     | Lateral movement                                             |
| Active   Directory attributes reconnaissance (LDAP)          | 2210                | Medium                                                   | Discovery                                                    |
| Suspected   SMB packet manipulation (CVE-2020-0796 exploitation) - (preview) | 2406                | High                                                     | Lateral movement                                             |
| Suspected   Kerberos SPN exposure (external ID 2410)         | 2410                | High                                                     | Credential access                                            |
| Suspected   Netlogon privilege elevation attempt (CVE-2020-1472 exploitation) | 2411                | High                                                     | Privilege Escalation                                         |
| Suspected   AS-REP Roasting attack                           | 2412                | High                                                     | Credential access                                            |
| Exchange   Server Remote Code Execution (CVE-2021-26855)     | 2414                | High                                                     | Lateral movement                                             |
| Suspected   exploitation attempt on Windows Print Spooler service | 2415                | High or Medium                                           | Lateral movement                                             |
| Suspicious   network connection over Encrypting File System Remote Protocol | 2416                | High or Medium                                           | Lateral movement                                             |
| Suspicious modification of a sAMNameAccount attribute (CVE-2021-42278 and CVE-2021-42287 exploitation) | 2419                | High                                                     | Credential access                                            |

> [!NOTE]
> To disable any security alert, contact support.

## See Also

- [Working with security alerts](/defender-for-identity/manage-security-alerts)
- [Understanding security alerts](understanding-security-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)