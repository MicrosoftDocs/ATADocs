---
# required metadata

title: Azure ATP security alert guide | Microsoft Docs
d|Description: This article provides a list of the security alerts issued by Azure ATP.
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 05/27/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: ca5d1c7b-11a9-4df3-84a5-f53feaf6e561

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---


# Azure ATP Security Alerts

Azure ATP security alerts explain the suspicious activities detected by Azure ATP sensors on your network, and the actors and computers involved in each threat.   Alert evidence lists contain direct links to the involved users and computers, to help make your investigations easy and direct.

Azure ATP security alerts are divided into the following categories or phases, like the phases seen in a typical cyber-attack kill chain. Learn more about each phase, the alerts designed to detect each attack, and how to use the alerts to help protect your network using the following links:

  1. [Reconnaissance phase alerts](atp-reconnaissance-alerts.md)
  2. [Compromised credential phase alerts](atp-compromised-credentials-alerts.md)
  3. [Lateral movement phase alerts](atp-lateral-movement-alerts.md)
  4. [Domain dominance phase alerts](atp-domain-dominance-alerts.md)
  5. [Exfiltration phase alerts](atp-exfiltration-alerts.md)

To learn more about the structure and common components of all Azure ATP security alerts, see [Understanding security alerts](understanding-security-alerts.md).

## Security alert name mapping and unique external IDs

In version 2.56, all existing Azure ATP security alerts were renamed with easier to understand names. Mapping between old and new names, and their corresponding unique externalIds are as listed in the following table. When used with scripts or automation, Microsoft recommends use of alert external IDs in place of alert names, as only security alert external IDs are permanent, and not subject to change.

> [!div class="mx-tableFixed"] 

|New security alert name|Previous security alert name|Unique external ID|Severity|MITRE ATT&CK Matrix™ |
|---------|----------|---------|---------|---------|
|[Account enumeration reconnaissance](atp-reconnaissance-alerts.md#account-enumeration-reconnaissance-external-id-2003)|Reconnaissance using account enumeration|2003|Medium|Discovery|
|[Data exfiltration over SMB](atp-exfiltration-alerts.md#data-exfiltration-over-smb-external-id-2030)| NA| 2030|High|Exfiltration,<br>Lateral movement,<br>Command and control|
|[Honeytoken activity](atp-compromised-credentials-alerts.md#honeytoken-activity-external-id-2014)|Honeytoken activity|2014|Medium|Credential access,<br> Discovery|
|[Malicious request of Data Protection API master key](atp-domain-dominance-alerts.md#malicious-request-of-data-protection-api-master-key-external-id-2020)|Malicious Data Protection Private Information Request|2020|High|Credential access|
|[Network mapping reconnaissance (DNS)](atp-reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007)|Reconnaissance using DNS|2007|Medium|Discovery|
|[Remote code execution attempt](atp-domain-dominance-alerts.md#remote-code-execution-attempt-external-id-2019)|Remote code execution attempt|2019|Medium|Execution,<br> Persistence,<br> Privilege escalation,<br> Defense evasion,<br> Lateral movement|
|[Remote code execution over DNS](atp-lateral-movement-alerts.md#remote-code-execution-over-dns-external-id-2036)|NA|2036|Medium|Privilege escalation,<br> Lateral movement|
|[Security principal reconnaissance (LDAP)](atp-reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038)|NA|2038|Medium|Credential access|
|[Suspected brute force attack (Kerberos, NTLM)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-kerberos-ntlm-external-id-2023)|Suspicious authentication failures|2023|Medium|Credential access|
|[Suspected brute force attack (LDAP)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-ldap-external-id-2004)|Brute force attack using LDAP simple bind|2004|Medium|Credential access|
|[Suspected brute force attack (SMB)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-smb-external-id-2033)|Unusual protocol implementation (potential use of malicious tools such as Hydra)|2033|Medium|Lateral movement|
|[Suspected DCShadow attack (domain controller promotion)](atp-domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-promotion-external-id-2028)|Suspicious domain controller promotion (potential DCShadow attack)|2028|High|Defense evasion|
|[Suspected DCShadow attack (domain controller replication request)](atp-domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-replication-request-external-id-2029)|Suspicious domain controller replication request (potential DCShadow attack)|2029|High|Defense evasion|
|[Suspected DCSync attack (replication of directory services)](atp-domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006)|Malicious replication of directory services|2006|High|Persistence,<br> Credential access|
|[Suspected Golden Ticket usage (encryption downgrade)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-encryption-downgrade-external-id-2009)|Encryption downgrade activity (potential golden ticket attack)|2009|Medium|Privilege Escalation,<br> Lateral movement,<br>Persistence|
|[Suspected Golden Ticket usage (forged authorization data)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-forged-authorization-data-external-id-2013)|Privilege escalation using forged authorization data|2013|High|Privilege escalation,<br>Lateral movement,<br>Persistence|
|[Suspected Golden Ticket usage (nonexistent account)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-nonexistent-account-external-id-2027)|Kerberos Golden Ticket - nonexistent account|2027|High|Privilege Escalation,<br> Lateral movement,<br>Persistence|
|[Suspected Golden Ticket usage (ticket anomaly)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-external-id-2032)|NA|2032|High|Privilege Escalation,<br> Lateral movement,<br>Persistence|
|[Suspected Golden Ticket usage (time anomaly)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-time-anomaly-external-id-2022)|Kerberos Golden Ticket - time anomaly|2022|High|Privilege Escalation,<br> Lateral movement,<br>Persistence|
|[Suspected identity theft (pass-the-hash)](atp-lateral-movement-alerts.md#suspected-identity-theft-pass-the-hash-external-id-2017)|Identity theft using Pass-the-Hash attack|2017|High|Lateral movement|
|[Suspected identity theft (pass-the-ticket)](atp-lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018)|Identity theft using Pass-the-Ticket attack|2018|High or Medium|Lateral movement|
|[Suspected over-pass-the-hash attack (encryption downgrade)](atp-lateral-movement-alerts.md#suspected-overpass-the-hash-attack-encryption-downgrade-external-id-2008)|Encryption downgrade activity (potential overpass-the-hash attack)|2008|Medium|Lateral movement|
|[Suspected overpass-the-hash attack (Kerberos)](atp-lateral-movement-alerts.md#suspected-overpass-the-hash-attack-kerberos-external-id-2002)|Unusual Kerberos protocol implementation (potential overpass-the-hash attack)|2002|Medium|Lateral movement|
|[Suspected skeleton key attack (encryption downgrade)](atp-domain-dominance-alerts.md#suspected-skeleton-key-attack-encryption-downgrade-external-id-2010)|Encryption downgrade activity (potential skeleton key attack)|2010|Medium|Lateral movement,<br> Persistence|
|[Suspected use of Metasploit hacking framework](atp-compromised-credentials-alerts.md#suspected-use-of-metasploit-hacking-framework-external-id-2034)|Unusual protocol implementation (potential use of Metasploit hacking tools)|2034|Medium|Lateral movement|
|[Suspected NTLM relay attack (Exchange account) - preview](atp-lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037---preview)|NA|2037|Medium or Low if observed using signed NTLM v2 protocol|Privilege escalation, <br> Lateral movement|
|[Suspected WannaCry ransomware attack](atp-compromised-credentials-alerts.md#suspected-wannacry-ransomware-attack-external-id-2035)|Unusual protocol implementation (potential WannaCry ransomware attack)|2035|Medium|Lateral movement|
|[Suspicious communication over DNS](atp-exfiltration-alerts.md#suspicious-communication-over-dns-external-id-2031)|Suspicious communication over DNS|2031|Medium|Exfiltration|
|[Suspicious additions to sensitive groups](atp-domain-dominance-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024)|Suspicious additions to sensitive groups|2024|Medium|Credential access,<br>Persistence|
|[Suspicious service creation](atp-domain-dominance-alerts.md#suspicious-service-creation-external-id-2026)|Suspicious service creation|2026|Medium|Execution,<br> Persistence,<br> Privilege Escalation,<br> Defense evasion,<br>Lateral movement|
|[Suspicious VPN connection](atp-compromised-credentials-alerts.md#suspicious-vpn-connection-external-id-2025)|Suspicious VPN connection|2025|Medium|Persistence,<br>Defense evasion|
|[User and group membership reconnaissance (SAMR)](atp-reconnaissance-alerts.md#user-and-group-membership-reconnaissance-samr-external-id-2021)|Reconnaissance using directory services queries|2021|Medium|Discovery|
|[User and IP address reconnaissance (SMB)](atp-reconnaissance-alerts.md#user-and-ip-address-reconnaissance-smb-external-id-2012)|Reconnaissance using SMB Session Enumeration|2012|Medium|Discovery|
|

> [!NOTE]
> To disable any security alert, contact support.


## See Also
- [Working with security alerts](working-with-suspicious-activities.md)
- [Understanding security alerts](understanding-security-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
