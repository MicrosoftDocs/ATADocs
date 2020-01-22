---
# required metadata

title: Azure ATP security alert guide
d|Description: This article provides a list of the security alerts issued by Azure ATP.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 01/22/2020
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

> [!NOTE]
> The Azure ATP features explained on this page are also accessible using the new [portal](https://portal.cloudappsecurity.com).

Azure ATP security alerts explain the suspicious activities detected by Azure ATP sensors on your network, and the actors and computers involved in each threat. Alert evidence lists contain direct links to the involved users and computers, to help make your investigations easy and direct.

Azure ATP security alerts are divided into the following categories or phases, like the phases seen in a typical cyber-attack kill chain. Learn more about each phase, the alerts designed to detect each attack, and how to use the alerts to help protect your network using the following links:

  1. [Reconnaissance phase alerts](atp-reconnaissance-alerts.md)
  2. [Compromised credential phase alerts](atp-compromised-credentials-alerts.md)
  3. [Lateral movement phase alerts](atp-lateral-movement-alerts.md)
  4. [Domain dominance phase alerts](atp-domain-dominance-alerts.md)
  5. [Exfiltration phase alerts](atp-exfiltration-alerts.md)

To learn more about the structure and common components of all Azure ATP security alerts, see [Understanding security alerts](understanding-security-alerts.md).

## Security alert name mapping and unique external IDs

The following table lists the mapping between alert names, their corresponding unique external IDs, and their Microsoft Cloud App Security alert IDs. When used with scripts or automation, Microsoft recommends use of alert external IDs in place of alert names, as only security alert external IDs are permanent, and not subject to change.

> [!div class="mx-tdBreakAll"]
> |New security alert name|Unique external ID|Severity|MITRE ATT&CK Matrix™|Cloud App Security alert ID|
> |---|---|---|---|---|
> |[Account enumeration reconnaissance](atp-reconnaissance-alerts.md#account-enumeration-reconnaissance-external-id-2003)|2003|Medium|Discovery|ALERT_EXTERNAL_AATP_ACCOUNT_ENUMERATION_SECURITY_ALERT|
> |[Data exfiltration over SMB](atp-exfiltration-alerts.md#data-exfiltration-over-smb-external-id-2030)|2030|High|Exfiltration,<br>Lateral movement,<br>Command and control|ALERT_EXTERNAL_AATP_SMB_DATA_EXFILTRATION_SECURITY_ALERT|
> |[Honeytoken activity](atp-compromised-credentials-alerts.md#honeytoken-activity-external-id-2014)|2014|Medium|Credential access,<br>Discovery|ALERT_EXTERNAL_AATP_HONEYTOKEN_ACTIVITY_SECURITY_ALERT|
> |[Malicious request of Data Protection API master key](atp-domain-dominance-alerts.md#malicious-request-of-data-protection-api-master-key-external-id-2020)|2020|High|Credential access|ALERT_EXTERNAL_AATP_RETRIEVE_DATA_PROTECTION_BACKUP_KEY_SECURITY_ALERT|
> |[Network mapping reconnaissance (DNS)](atp-reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007)|2007|Medium|Discovery|ALERT_EXTERNAL_AATP_DNS_RECONNAISSANCE_SECURITY_ALERT|
> |[Remote code execution attempt](atp-domain-dominance-alerts.md#remote-code-execution-attempt-external-id-2019)|2019|Medium|Execution,<br>Persistence,<br>Privilege escalation,<br>Defense evasion,<br>Lateral movement|ALERT_EXTERNAL_AATP_REMOTE_EXECUTION_SECURITY_ALERT|
> |[Remote code execution over DNS](atp-lateral-movement-alerts.md#remote-code-execution-over-dns-external-id-2036)|2036|Medium|Privilege escalation,<br>Lateral movement|ALERT_EXTERNAL_AATP_DNS_REMOTE_CODE_EXECUTION_SECURITY_ALERT|
> |[Security principal reconnaissance (LDAP)](atp-reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038)|2038|Medium|Credential access|ALERT_EXTERNAL_AATP_LDAP_SEARCH_RECONNAISSANCE_SECURITY_ALERT|
> |[Suspected brute force attack (Kerberos, NTLM)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-kerberos-ntlm-external-id-2023)|2023|Medium|Credential access|ALERT_EXTERNAL_AATP_BRUTE_FORCE_SECURITY_ALERT|
> |[Suspected brute force attack (LDAP)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-ldap-external-id-2004)|2004|Medium|Credential access|ALERT_EXTERNAL_AATP_LDAP_BRUTE_FORCE_SECURITY_ALERT|
> |[Suspected brute force attack (SMB)](atp-compromised-credentials-alerts.md#suspected-brute-force-attack-smb-external-id-2033)|2033|Medium|Lateral movement|ALERT_EXTERNAL_AATP_ABNORMAL_SMB_BRUTE_FORCE_SECURITY_ALERT|
> |[Suspected DCShadow attack (domain controller promotion)](atp-domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-promotion-external-id-2028)|2028|High|Defense evasion|ALERT_EXTERNAL_AATP_DIRECTORY_SERVICES_ROGUE_PROMOTION_SECURITY_ALERT|
> |[Suspected DCShadow attack (domain controller replication request)](atp-domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-replication-request-external-id-2029)|2029|High|Defense evasion|ALERT_EXTERNAL_AATP_DIRECTORY_SERVICES_ROGUE_REPLICATION_SECURITY_ALERT|
> |[Suspected DCSync attack (replication of directory services)](atp-domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006)|2006|High|Persistence,<br>Credential access|ALERT_EXTERNAL_AATP_DIRECTORY_SERVICES_REPLICATION_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (encryption downgrade)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-encryption-downgrade-external-id-2009)|2009|Medium|Privilege Escalation,<br>Lateral movement,<br>Persistence|ALERT_EXTERNAL_AATP_GOLDEN_TICKET_ENCRYPTION_DOWNGRADE_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (forged authorization data)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-forged-authorization-data-external-id-2013)|2013|High|Privilege escalation,<br>Lateral movement,<br>Persistence|ALERT_EXTERNAL_AATP_FORGED_PAC_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (nonexistent account)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-nonexistent-account-external-id-2027)|2027|High|Privilege Escalation,<br>Lateral movement,<br>Persistence|ALERT_EXTERNAL_AATP_FORGED_PRINCIPAL_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (ticket anomaly)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-external-id-2032)|2032|High|Privilege Escalation,<br>Lateral movement,<br>Persistence|ALERT_EXTERNAL_AATP_GOLDEN_TICKET_SIZE_ANOMALY_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (time anomaly)](atp-domain-dominance-alerts.md#suspected-golden-ticket-usage-time-anomaly-external-id-2022)|2022|High|Privilege Escalation,<br>Lateral movement,<br>Persistence|ALERT_EXTERNAL_AATP_GOLDEN_TICKET_SECURITY_ALERT|
> |[Suspected identity theft (pass-the-hash)](atp-lateral-movement-alerts.md#suspected-identity-theft-pass-the-hash-external-id-2017)|2017|High|Lateral movement|ALERT_EXTERNAL_AATP_PASS_THE_HASH_SECURITY_ALERT|
> |[Suspected identity theft (pass-the-ticket)](atp-lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018)|2018|High or Medium|Lateral movement|ALERT_EXTERNAL_AATP_PASS_THE_TICKET_SECURITY_ALERT|
> |[Suspected NTLM authentication tampering](atp-lateral-movement-alerts.md#suspected-ntlm-authentication-tampering-external-id-2039)|2039|Medium|Privilege escalation, <br>Lateral movement|ALERT_EXTERNAL_AATP_ABNORMAL_NTLM_SIGNING_SECURITY_ALERT|
> |[Suspected NTLM relay attack](atp-lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037)|2037|Medium or Low if observed using signed NTLM v2 protocol|Privilege escalation, <br>Lateral movement|ALERT_EXTERNAL_AATP_NTLM_RELAY_SECURITY_ALERT|
> |[Suspected over-pass-the-hash attack (encryption downgrade)](atp-lateral-movement-alerts.md#suspected-overpass-the-hash-attack-encryption-downgrade-external-id-2008)|2008|Medium|Lateral movement|ALERT_EXTERNAL_AATP_OVERPASS_THE_HASH_ENCRYPTION_DOWNGRADE_SECURITY_ALERT|
> |[Suspected overpass-the-hash attack (Kerberos)](atp-lateral-movement-alerts.md#suspected-overpass-the-hash-attack-kerberos-external-id-2002)|2002|Medium|Lateral movement|ALERT_EXTERNAL_AATP_ABNORMAL_KERBEROS_OVERPASS_THE_HASH_SECURITY_ALERT|
> |[Suspected skeleton key attack (encryption downgrade)](atp-domain-dominance-alerts.md#suspected-skeleton-key-attack-encryption-downgrade-external-id-2010)|2010|Medium|Lateral movement,<br>Persistence|ALERT_EXTERNAL_AATP_SKELETON_KEY_ENCRYPTION_DOWNGRADE_SECURITY_ALERT|
> |[Suspected use of Metasploit hacking framework](atp-compromised-credentials-alerts.md#suspected-use-of-metasploit-hacking-framework-external-id-2034)|2034|Medium|Lateral movement|ALERT_EXTERNAL_AATP_ABNORMAL_SMB_METASPLOIT_SECURITY_ALERT|
> |[Suspected WannaCry ransomware attack](atp-compromised-credentials-alerts.md#suspected-wannacry-ransomware-attack-external-id-2035)|2035|Medium|Lateral movement|ALERT_EXTERNAL_AATP_ABNORMAL_SMB_WANNA_CRY_SECURITY_ALERT|
> |[Suspicious additions to sensitive groups](atp-domain-dominance-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024)|2024|Medium|Credential access,<br>Persistence|ALERT_EXTERNAL_AATP_ABNORMAL_SENSITIVE_GROUP_MEMBERSHIP_CHANGE_SECURITY_ALERT|
> |[Suspicious communication over DNS](atp-exfiltration-alerts.md#suspicious-communication-over-dns-external-id-2031)|2031|Medium|Exfiltration|ALERT_EXTERNAL_AATP_DNS_SUSPICIOUS_COMMUNICATION_SECURITY_ALERT|
> |[Suspicious service creation](atp-domain-dominance-alerts.md#suspicious-service-creation-external-id-2026)|2026|Medium|Execution,<br>Persistence,<br>Privilege Escalation,<br>Defense evasion,<br>Lateral movement|ALERT_EXTERNAL_AATP_MALICIOUS_SERVICE_CREATION_SECURITY_ALERT|
> |[Suspicious VPN connection](atp-compromised-credentials-alerts.md#suspicious-vpn-connection-external-id-2025)|2025|Medium|Persistence,<br>Defense evasion|ALERT_EXTERNAL_AATP_ABNORMAL_VPN_SECURITY_ALERT|
> |[User and group membership reconnaissance (SAMR)](atp-reconnaissance-alerts.md#user-and-group-membership-reconnaissance-samr-external-id-2021)|2021|Medium|Discovery|ALERT_EXTERNAL_AATP_SAMR_RECONNAISSANCE_SECURITY_ALERT|
> |[User and IP address reconnaissance (SMB)](atp-reconnaissance-alerts.md#user-and-ip-address-reconnaissance-smb-external-id-2012)|2012|Medium|Discovery|ALERT_EXTERNAL_AATP_ENUMERATE_SESSIONS_SECURITY_ALERT|

> [!NOTE]
> To disable any security alert, contact support.

## See Also

- [Working with security alerts](working-with-suspicious-activities.md)
- [Understanding security alerts](understanding-security-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
