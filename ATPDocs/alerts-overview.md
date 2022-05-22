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
| [Suspected   overpass-the-hash attack (Kerberos)](lateral-movement-alerts.md#suspected-overpass-the-hash-attack-kerberos-external-id-2002) | 2002                | Medium                                                   | Lateral movement                                             |
| [Account   enumeration reconnaissance](reconnaissance-alerts.md#account-enumeration-reconnaissance-external-id-2003) | 2003                | Medium                                                   | Discovery                                                    |
| [Suspected   Brute Force attack (LDAP)](compromised-credentials-alerts.md#suspected-brute-force-attack-ldap-external-id-2004) | 2004                | Medium                                                   | Credential access                                            |
| [Suspected   DCSync attack (replication of directory services)](domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006) | 2006                | High                                                     | Persistence,  Credential access                              |
| [Network   mapping reconnaissance (DNS)](reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007) | 2007                | Medium                                                   | Discovery                                                    |
| [Suspected   Golden Ticket usage (encryption downgrade)](domain-dominance-alerts.md#suspected-golden-ticket-usage-encryption-downgrade-external-id-2009) | 2009                | Medium                                                   | Privilege Escalation, Lateral movement, Persistence          |
| [Suspected   Skeleton Key attack (encryption downgrade)](domain-dominance-alerts.md#suspected-skeleton-key-attack-encryption-downgrade-external-id-2010) | 2010                | Medium                                                   | Lateral movement, Persistence                                |
| [User   and IP address reconnaissance (SMB)](reconnaissance-alerts.md#user-and-ip-address-reconnaissance-smb-external-id-2012) | 2012                | Medium                                                   | Discovery                                                    |
| [Suspected   Golden Ticket usage (forged authorization data)](domain-dominance-alerts.md#suspected-golden-ticket-usage-forged-authorization-data-external-id-2013) | 2013                | High                                                     | Privilege escalation, Lateral movement, Persistence          |
| [Honeytoken   activity](compromised-credentials-alerts.md#honeytoken-activity-external-id-2014) | 2014                | Medium                                                   | Credential access, Discovery                                 |
| [Suspected   identity theft (pass-the-hash)](lateral-movement-alerts.md#suspected-identity-theft-pass-the-hash-external-id-2017) | 2017                | High                                                     | Lateral movement                                             |
| [Suspected   identity theft (pass-the-ticket)](lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018) | 2018                | High or Medium                                           | Lateral movement                                             |
| [Remote   code execution attempt](domain-dominance-alerts.md#remote-code-execution-attempt-external-id-2019) | 2019                | Medium                                                   | Execution,  Persistence, Privilege escalation, Defense evasion, Lateral movement |
| [Malicious   request of Data Protection API master key](domain-dominance-alerts.md#malicious-request-of-data-protection-api-master-key-external-id-2020) | 2020                | High                                                     | Credential access                                            |
| [User   and Group membership reconnaissance (SAMR)](reconnaissance-alerts.md#user-and-group-membership-reconnaissance-samr-external-id-2021) | 2021                | Medium                                                   | Discovery                                                    |
| [Suspected   Golden Ticket usage (time anomaly)](domain-dominance-alerts.md#suspected-golden-ticket-usage-time-anomaly-external-id-2022) | 2022                | High                                                     | Privilege Escalation, Lateral movement, Persistence          |
| [Suspected   Brute Force attack (Kerberos, NTLM)](compromised-credentials-alerts.md#suspected-brute-force-attack-kerberos-ntlm-external-id-2023) | 2023                | Medium                                                   | Credential access                                            |
| [Suspicious   additions to sensitive groups](domain-dominance-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024) | 2024                | Medium                                                   | Credential access, Persistence                               |
| [Suspicious   VPN connection](compromised-credentials-alerts.md#suspicious-vpn-connection-external-id-2025) | 2025                | Medium                                                   | Persistence,  Defense evasion                                |
| [Suspicious   service creation](domain-dominance-alerts.md#suspicious-service-creation-external-id-2026) | 2026                | Medium                                                   | Execution,  Persistence, Privilege Escalation, Defense evasion, Lateral movement |
| [Suspected   Golden Ticket usage (nonexistent account)](domain-dominance-alerts.md#suspected-golden-ticket-usage-nonexistent-account-external-id-2027) | 2027                | High                                                     | Privilege Escalation, Lateral movement, Persistence          |
| [Suspected   DCShadow attack (domain controller promotion)](domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-promotion-external-id-2028) | 2028                | High                                                     | Defense evasion                                              |
| [Suspected   DCShadow attack (domain controller replication request)](domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-replication-request-external-id-2029) | 2029                | High                                                     | Defense evasion                                              |
| [Data   exfiltration over SMB](exfiltration-alerts.md#data-exfiltration-over-smb-external-id-2030) | 2030                | High                                                     | Exfiltration, Lateral movement, Command and control          |
| [Suspicious   communication over DNS](exfiltration-alerts.md#suspicious-communication-over-dns-external-id-2031) | 2031                | Medium                                                   | Exfiltration                                                 |
| [Suspected   Golden Ticket usage (ticket anomaly)](domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-external-id-2032) | 2032                | High                                                     | Privilege Escalation, Lateral movement, Persistence          |
| [Suspected   Brute Force attack (SMB)](compromised-credentials-alerts.md#suspected-brute-force-attack-smb-external-id-2033) | 2033                | Medium                                                   | Lateral movement                                             |
| [Suspected   use of Metasploit hacking framework](compromised-credentials-alerts.md#suspected-use-of-metasploit-hacking-framework-external-id-2034) | 2034                | Medium                                                   | Lateral movement                                             |
| [Suspected   WannaCry ransomware attack](compromised-credentials-alerts.md#suspected-wannacry-ransomware-attack-external-id-2035) | 2035                | Medium                                                   | Lateral movement                                             |
| [Remote code execution over DNS](lateral-movement-alerts.md#remote-code-execution-attempt-over-dns-external-id-2036) | 2036                | Medium                                                   | Privilege escalation, Lateral movement                       |
| [Suspected   NTLM relay attack](lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037) | 2037                | Medium or Low if observed  using signed NTLM v2 protocol | Privilege escalation, Lateral  movement                      |
| [Security   principal reconnaissance (LDAP)](reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038) | 2038                | Medium                                                   | Credential access                                            |
| [Suspected   NTLM authentication tampering](lateral-movement-alerts.md#suspected-ntlm-authentication-tampering-external-id-2039) | 2039                | Medium                                                   | Privilege escalation, Lateral  movement                      |
| [Suspected   Golden Ticket usage (ticket anomaly using RBCD)](domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-using-rbcd-external-id-2040) | 2040                | High                                                     | Persistence                                                  |
| [Suspected   rogue Kerberos certificate usage](lateral-movement-alerts.md#suspected-rogue-kerberos-certificate-usage-external-id-2047) | 2047                | High                                                     | Lateral movement                                             |
| [Active   Directory attributes reconnaissance (LDAP)](reconnaissance-alerts.md#active-directory-attributes-reconnaissance-ldap-external-id-2210) | 2210                | Medium                                                   | Discovery                                                    |
| [Suspected   SMB packet manipulation (CVE-2020-0796 exploitation) - (preview)](lateral-movement-alerts.md#suspected-smb-packet-manipulation-cve-2020-0796-exploitation-external-id-2406) | 2406                | High                                                     | Lateral movement                                             |
| [Suspected   Kerberos SPN exposure (external ID 2410)](compromised-credentials-alerts.md#suspected-kerberos-spn-exposure-external-id-2410) | 2410                | High                                                     | Credential access                                            |
| [Suspected   Netlogon privilege elevation attempt (CVE-2020-1472 exploitation)](compromised-credentials-alerts.md#suspected-netlogon-priv-elev-2411) | 2411                | High                                                     | Privilege Escalation                                         |
| [Suspected   AS-REP Roasting attack](compromised-credentials-alerts.md#suspected-as-rep-roasting-attack-external-id-2412) | 2412                | High                                                     | Credential access                                            |
| [Exchange   Server Remote Code Execution (CVE-2021-26855)](lateral-movement-alerts.md#exchange-server-remote-code-execution-cve-2021-26855-external-id-2414) | 2414                | High                                                     | Lateral movement                                             |
| [Suspected   exploitation attempt on Windows Print Spooler service](lateral-movement-alerts.md#suspected-exploitation-attempt-on-windows-print-spooler-service-external-id-2415) | 2415                | High or Medium                                           | Lateral movement                                             |
| [Suspicious   network connection over Encrypting File System Remote Protocol](lateral-movement-alerts.md#suspicious-network-connection-over-encrypting-file-system-remote-protocol-external-id-2416) | 2416                | High or Medium                                           | Lateral movement                                             |
| [Suspicious modification of a sAMNameAccount attribute (CVE-2021-42278 and CVE-2021-42287 exploitation)](compromised-credentials-alerts.md#suspicious-modification-of-a-samnameaccount-attribute-cve-2021-42278-and-cve-2021-42287-exploitation-external-id-2419) | 2419                |      High                                                    |                                     Credential access                         |

> [!NOTE]
> To disable any security alert, contact support.

## See Also

- [Working with security alerts](working-with-suspicious-activities.md)
- [Understanding security alerts](understanding-security-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
