---
title: Microsoft Defender for Identity security alert guide
description: This article provides a list of the security alerts issued by Microsoft Defender for Identity.
ms.date: 09/29/2021
ms.topic: conceptual
---

# Microsoft Defender for Identity Security Alerts

> [!NOTE]
> The [!INCLUDE [Product long](includes/product-long.md)] features explained on this page are also accessible using the new [portal](https://portal.cloudappsecurity.com).

[!INCLUDE [Product long](includes/product-long.md)] security alerts explain the suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] sensors on your network, and the actors and computers involved in each threat. Alert evidence lists contain direct links to the involved users and computers, to help make your investigations easy and direct.

[!INCLUDE [Product short](includes/product-short.md)] security alerts are divided into the following categories or phases, like the phases seen in a typical cyber-attack kill chain. Learn more about each phase, the alerts designed to detect each attack, and how to use the alerts to help protect your network using the following links:

1. [Reconnaissance phase alerts](reconnaissance-alerts.md)
1. [Compromised credential phase alerts](compromised-credentials-alerts.md)
1. [Lateral movement phase alerts](lateral-movement-alerts.md)
1. [Domain dominance phase alerts](domain-dominance-alerts.md)
1. [Exfiltration phase alerts](exfiltration-alerts.md)

To learn more about the structure and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md).

## Security alert name mapping and unique external IDs

The following table lists the mapping between alert names, their corresponding unique external IDs, and their Microsoft Defender for Cloud Apps alert IDs. When used with scripts or automation, Microsoft recommends use of alert external IDs in place of alert names, as only security alert external IDs are permanent, and not subject to change.

### [External IDs](#tab/external)

> [!div class="mx-tdBreakAll"]
> |Security alert name|Unique external ID|Severity|MITRE ATT&CK Matrix&trade;|
> |---|---|---|---|
> |[Account enumeration reconnaissance](reconnaissance-alerts.md#account-enumeration-reconnaissance-external-id-2003)|2003|Medium|Discovery|
> |[Active Directory attributes reconnaissance (LDAP)](reconnaissance-alerts.md#active-directory-attributes-reconnaissance-ldap-external-id-2210)|2210|Medium|Discovery|
> |[Data exfiltration over SMB](exfiltration-alerts.md#data-exfiltration-over-smb-external-id-2030)|2030|High|Exfiltration,<br>Lateral movement,<br>Command and control|
> |[Exchange Server Remote Code Execution (CVE-2021-26855)](lateral-movement-alerts.md#exchange-server-remote-code-execution-cve-2021-26855-external-id-2414)|2414|High|Lateral movement|
> |[Honeytoken activity](compromised-credentials-alerts.md#honeytoken-activity-external-id-2014)|2014|Medium|Credential access,<br>Discovery|
> |[Malicious request of Data Protection API master key](domain-dominance-alerts.md#malicious-request-of-data-protection-api-master-key-external-id-2020)|2020|High|Credential access|
> |[Network mapping reconnaissance (DNS)](reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007)|2007|Medium|Discovery|
> |[Remote code execution attempt](domain-dominance-alerts.md#remote-code-execution-attempt-external-id-2019)|2019|Medium|Execution,<br>Persistence,<br>Privilege escalation,<br>Defense evasion,<br>Lateral movement|
> |[Remote code execution over DNS](lateral-movement-alerts.md#remote-code-execution-over-dns-external-id-2036)|2036|Medium|Privilege escalation,<br>Lateral movement|
> |[Security principal reconnaissance (LDAP)](reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038)|2038|Medium|Credential access|
> |[Suspected AS-REP Roasting attack](compromised-credentials-alerts.md#suspected-as-rep-roasting-attack-external-id-2412)|2412|High|Credential access|
> |[Suspected Brute Force attack (Kerberos, NTLM)](compromised-credentials-alerts.md#suspected-brute-force-attack-kerberos-ntlm-external-id-2023)|2023|Medium|Credential access|
> |[Suspected Brute Force attack (LDAP)](compromised-credentials-alerts.md#suspected-brute-force-attack-ldap-external-id-2004)|2004|Medium|Credential access|
> |[Suspected Brute Force attack (SMB)](compromised-credentials-alerts.md#suspected-brute-force-attack-smb-external-id-2033)|2033|Medium|Lateral movement|
> |[Suspected DCShadow attack (domain controller promotion)](domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-promotion-external-id-2028)|2028|High|Defense evasion|
> |[Suspected DCShadow attack (domain controller replication request)](domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-replication-request-external-id-2029)|2029|High|Defense evasion|
> |[Suspected DCSync attack (replication of directory services)](domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006)|2006|High|Persistence,<br>Credential access|
> |[Suspected exploitation attempt on Windows Print Spooler service](lateral-movement-alerts.md#suspected-exploitation-attempt-on-windows-print-spooler-service-external-id-2415)|2415|High or Medium|Lateral movement|
> |[Suspected Golden Ticket usage (encryption downgrade)](domain-dominance-alerts.md#suspected-golden-ticket-usage-encryption-downgrade-external-id-2009)|2009|Medium|Privilege Escalation,<br>Lateral movement,<br>Persistence|
> |[Suspected Golden Ticket usage (forged authorization data)](domain-dominance-alerts.md#suspected-golden-ticket-usage-forged-authorization-data-external-id-2013)|2013|High|Privilege escalation,<br>Lateral movement,<br>Persistence|
> |[Suspected Golden Ticket usage (nonexistent account)](domain-dominance-alerts.md#suspected-golden-ticket-usage-nonexistent-account-external-id-2027)|2027|High|Privilege Escalation,<br>Lateral movement,<br>Persistence|
> |[Suspected Golden Ticket usage (ticket anomaly)](domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-external-id-2032)|2032|High|Privilege Escalation,<br>Lateral movement,<br>Persistence|
> |[Suspected Golden Ticket usage (ticket anomaly using RBCD)](domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-using-rbcd-external-id-2040)|2040|High|Persistence|
> |[Suspected Golden Ticket usage (time anomaly)](domain-dominance-alerts.md#suspected-golden-ticket-usage-time-anomaly-external-id-2022)|2022|High|Privilege Escalation,<br>Lateral movement,<br>Persistence|
> |[Suspected identity theft (pass-the-hash)](lateral-movement-alerts.md#suspected-identity-theft-pass-the-hash-external-id-2017)|2017|High|Lateral movement|
> |[Suspected identity theft (pass-the-ticket)](lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018)|2018|High or Medium|Lateral movement|
> |[Suspected Kerberos SPN exposure (external ID 2410)](compromised-credentials-alerts.md#suspected-kerberos-spn-exposure-external-id-2410)|2410|High|Credential access|
> |[Suspected Netlogon privilege elevation attempt (CVE-2020-1472 exploitation)](compromised-credentials-alerts.md#suspected-netlogon-priv-elev-2411)|2411|High|Privilege Escalation|
> |[Suspicious network connection over Encrypting File System Remote Protocol](lateral-movement-alerts.md#suspicious-network-connection-over-encrypting-file-system-remote-protocol-external-id-2416)|2416|High or Medium|Lateral movement|
> |[Suspected NTLM authentication tampering](lateral-movement-alerts.md#suspected-ntlm-authentication-tampering-external-id-2039)|2039|Medium|Privilege escalation, <br>Lateral movement|
> |[Suspected NTLM relay attack](lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037)|2037|Medium or Low if observed using signed NTLM v2 protocol|Privilege escalation, <br>Lateral movement|
> |[Suspected overpass-the-hash attack (Kerberos)](lateral-movement-alerts.md#suspected-overpass-the-hash-attack-kerberos-external-id-2002)|2002|Medium|Lateral movement|
> |[Suspected rogue Kerberos certificate usage](lateral-movement-alerts.md#suspected-rogue-kerberos-certificate-usage-external-id-2047)|2047|High|Lateral movement|
> |[Suspected Skeleton Key attack (encryption downgrade)](domain-dominance-alerts.md#suspected-skeleton-key-attack-encryption-downgrade-external-id-2010)|2010|Medium|Lateral movement,<br>Persistence|
> |[Suspected SMB packet manipulation (CVE-2020-0796 exploitation) - (preview)](lateral-movement-alerts.md#suspected-smb-packet-manipulation-cve-2020-0796-exploitation-external-id-2406)|2406|High|Lateral movement|
> |[Suspected use of Metasploit hacking framework](compromised-credentials-alerts.md#suspected-use-of-metasploit-hacking-framework-external-id-2034)|2034|Medium|Lateral movement|
> |[Suspected WannaCry ransomware attack](compromised-credentials-alerts.md#suspected-wannacry-ransomware-attack-external-id-2035)|2035|Medium|Lateral movement|
> |[Suspicious additions to sensitive groups](domain-dominance-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024)|2024|Medium|Credential access,<br>Persistence|
> |[Suspicious communication over DNS](exfiltration-alerts.md#suspicious-communication-over-dns-external-id-2031)|2031|Medium|Exfiltration|
> |[Suspicious service creation](domain-dominance-alerts.md#suspicious-service-creation-external-id-2026)|2026|Medium|Execution,<br>Persistence,<br>Privilege Escalation,<br>Defense evasion,<br>Lateral movement|
> |[Suspicious VPN connection](compromised-credentials-alerts.md#suspicious-vpn-connection-external-id-2025)|2025|Medium|Persistence,<br>Defense evasion|
> |[User and Group membership reconnaissance (SAMR)](reconnaissance-alerts.md#user-and-group-membership-reconnaissance-samr-external-id-2021)|2021|Medium|Discovery|
> |[User and IP address reconnaissance (SMB)](reconnaissance-alerts.md#user-and-ip-address-reconnaissance-smb-external-id-2012)|2012|Medium|Discovery|

### [Defender for Cloud Apps IDs](#tab/cloud-app-security)

> [!div class="mx-tdBreakAll"]
> |Security alert name|Defender for Cloud Apps alert ID|
> |---|---|
> |[Account enumeration reconnaissance](reconnaissance-alerts.md#account-enumeration-reconnaissance-external-id-2003)|ALERT_EXTERNAL_AATP_ACCOUNT_ENUMERATION_SECURITY_ALERT|
> |[Active Directory attributes reconnaissance (LDAP)](reconnaissance-alerts.md#active-directory-attributes-reconnaissance-ldap-external-id-2210)|ALERT_EXTERNAL_AATP_LDAP_SENSITIVE_ATTRIBUTE_RECONNAISSANCE_SECURITY_ALERT|
> |[Data exfiltration over SMB](exfiltration-alerts.md#data-exfiltration-over-smb-external-id-2030)|ALERT_EXTERNAL_AATP_SMB_DATA_EXFILTRATION_SECURITY_ALERT|
> |[Exchange Server Remote Code Execution (CVE-2021-26855)](lateral-movement-alerts.md#exchange-server-remote-code-execution-cve-2021-26855-external-id-2414)|ALERT_EXTERNAL_AATP_EXCHANGE_SERVER_REMOTE_CODE_EXECUTION_SECURITY_ALERT|
> |[Honeytoken activity](compromised-credentials-alerts.md#honeytoken-activity-external-id-2014)|ALERT_EXTERNAL_AATP_HONEYTOKEN_ACTIVITY_SECURITY_ALERT|
> |[Malicious request of Data Protection API master key](domain-dominance-alerts.md#malicious-request-of-data-protection-api-master-key-external-id-2020)|ALERT_EXTERNAL_AATP_RETRIEVE_DATA_PROTECTION_BACKUP_KEY_SECURITY_ALERT|
> |[Network mapping reconnaissance (DNS)](reconnaissance-alerts.md#network-mapping-reconnaissance-dns-external-id-2007)|ALERT_EXTERNAL_AATP_DNS_RECONNAISSANCE_SECURITY_ALERT|
> |[Remote code execution attempt](domain-dominance-alerts.md#remote-code-execution-attempt-external-id-2019)|ALERT_EXTERNAL_AATP_REMOTE_EXECUTION_SECURITY_ALERT|
> |[Remote code execution over DNS](lateral-movement-alerts.md#remote-code-execution-over-dns-external-id-2036)|ALERT_EXTERNAL_AATP_DNS_REMOTE_CODE_EXECUTION_SECURITY_ALERT|
> |[Security principal reconnaissance (LDAP)](reconnaissance-alerts.md#security-principal-reconnaissance-ldap-external-id-2038)|ALERT_EXTERNAL_AATP_LDAP_SEARCH_RECONNAISSANCE_SECURITY_ALERT|
> |[Suspected AS-REP Roasting attack](compromised-credentials-alerts.md#suspected-as-rep-roasting-attack-external-id-2412)|ALERT_EXTERNAL_AATP_AS_REP_ROASTING_SECURITY_ALERT|
> |[Suspected Brute Force attack (Kerberos, NTLM)](compromised-credentials-alerts.md#suspected-brute-force-attack-kerberos-ntlm-external-id-2023)|ALERT_EXTERNAL_AATP_BRUTE_FORCE_SECURITY_ALERT|
> |[Suspected Brute Force attack (LDAP)](compromised-credentials-alerts.md#suspected-brute-force-attack-ldap-external-id-2004)|ALERT_EXTERNAL_AATP_LDAP_BRUTE_FORCE_SECURITY_ALERT|
> |[Suspected Brute Force attack (SMB)](compromised-credentials-alerts.md#suspected-brute-force-attack-smb-external-id-2033)|ALERT_EXTERNAL_AATP_ABNORMAL_SMB_BRUTE_FORCE_SECURITY_ALERT|
> |[Suspected DCShadow attack (domain controller promotion)](domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-promotion-external-id-2028)|ALERT_EXTERNAL_AATP_DIRECTORY_SERVICES_ROGUE_PROMOTION_SECURITY_ALERT|
> |[Suspected DCShadow attack (domain controller replication request)](domain-dominance-alerts.md#suspected-dcshadow-attack-domain-controller-replication-request-external-id-2029)|ALERT_EXTERNAL_AATP_DIRECTORY_SERVICES_ROGUE_REPLICATION_SECURITY_ALERT|
> |[Suspected DCSync attack (replication of directory services)](domain-dominance-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006)|ALERT_EXTERNAL_AATP_DIRECTORY_SERVICES_REPLICATION_SECURITY_ALERT|
> |[Suspected exploitation attempt on Windows Print Spooler service](lateral-movement-alerts.md#suspected-exploitation-attempt-on-windows-print-spooler-service-external-id-2415)|ALERT_EXTERNAL_AATP_PRINT_NIGHTMARE_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (encryption downgrade)](domain-dominance-alerts.md#suspected-golden-ticket-usage-encryption-downgrade-external-id-2009)|ALERT_EXTERNAL_AATP_GOLDEN_TICKET_ENCRYPTION_DOWNGRADE_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (forged authorization data)](domain-dominance-alerts.md#suspected-golden-ticket-usage-forged-authorization-data-external-id-2013)|ALERT_EXTERNAL_AATP_FORGED_PAC_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (nonexistent account)](domain-dominance-alerts.md#suspected-golden-ticket-usage-nonexistent-account-external-id-2027)|ALERT_EXTERNAL_AATP_FORGED_PRINCIPAL_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (ticket anomaly)](domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-external-id-2032)|ALERT_EXTERNAL_AATP_GOLDEN_TICKET_SIZE_ANOMALY_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (ticket anomaly using RBCD)](domain-dominance-alerts.md#suspected-golden-ticket-usage-ticket-anomaly-using-rbcd-external-id-2040)|ALERT_EXTERNAL_AATP_RESOURCE_BASED_CONSTRAINED_DELEGATION_GOLDEN_TICKET_SECURITY_ALERT|
> |[Suspected Golden Ticket usage (time anomaly)](domain-dominance-alerts.md#suspected-golden-ticket-usage-time-anomaly-external-id-2022)|ALERT_EXTERNAL_AATP_GOLDEN_TICKET_SECURITY_ALERT|
> |[Suspected identity theft (pass-the-hash)](lateral-movement-alerts.md#suspected-identity-theft-pass-the-hash-external-id-2017)|ALERT_EXTERNAL_AATP_PASS_THE_HASH_SECURITY_ALERT|
> |[Suspected identity theft (pass-the-ticket)](lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018)|ALERT_EXTERNAL_AATP_PASS_THE_TICKET_SECURITY_ALERT|
> |[Suspected Kerberos SPN exposure (external ID 2410)](compromised-credentials-alerts.md#suspected-kerberos-spn-exposure-external-id-2410)|ALERT_EXTERNAL_AATP_KERBEROASTING_SECURITY_ALERT|
> |[Suspected Netlogon privilege elevation attempt (CVE-2020-1472 exploitation)](compromised-credentials-alerts.md#suspected-netlogon-priv-elev-2411)|ALERT_EXTERNAL_AATP_NETLOGON_BYPASS_SECURITY_ALERT|
> |[Suspicious network connection over Encrypting File System Remote Protocol](lateral-movement-alerts.md#suspicious-network-connection-over-encrypting-file-system-remote-protocol-external-id-2416)|ALERT_EXTERNAL_AATP_PETIT_POTAM_SECURITY_ALERT|
> |[Suspected NTLM authentication tampering](lateral-movement-alerts.md#suspected-ntlm-authentication-tampering-external-id-2039)|ALERT_EXTERNAL_AATP_ABNORMAL_NTLM_SIGNING_SECURITY_ALERT|
> |[Suspected NTLM relay attack](lateral-movement-alerts.md#suspected-ntlm-relay-attack-exchange-account-external-id-2037)|ALERT_EXTERNAL_AATP_NTLM_RELAY_SECURITY_ALERT|
> |[Suspected overpass-the-hash attack (Kerberos)](lateral-movement-alerts.md#suspected-overpass-the-hash-attack-kerberos-external-id-2002)|ALERT_EXTERNAL_AATP_ABNORMAL_KERBEROS_OVERPASS_THE_HASH_SECURITY_ALERT|
> |[Suspected rogue Kerberos certificate usage](lateral-movement-alerts.md#suspected-rogue-kerberos-certificate-usage-external-id-2047)|ALERT_EXTERNAL_AATP_ROGUE_CERTIFICATE_USAGE_SECURITY_ALERT|
> |[Suspected Skeleton Key attack (encryption downgrade)](domain-dominance-alerts.md#suspected-skeleton-key-attack-encryption-downgrade-external-id-2010)|ALERT_EXTERNAL_AATP_SKELETON_KEY_ENCRYPTION_DOWNGRADE_SECURITY_ALERT|
> |[Suspected SMB packet manipulation (CVE-2020-0796 exploitation) - (preview)](lateral-movement-alerts.md#suspected-smb-packet-manipulation-cve-2020-0796-exploitation-external-id-2406)|ALERT_EXTERNAL_AATP_SMB_GHOST_SECURITY_ALERT|
> |[Suspected use of Metasploit hacking framework](compromised-credentials-alerts.md#suspected-use-of-metasploit-hacking-framework-external-id-2034)|ALERT_EXTERNAL_AATP_ABNORMAL_SMB_METASPLOIT_SECURITY_ALERT|
> |[Suspected WannaCry ransomware attack](compromised-credentials-alerts.md#suspected-wannacry-ransomware-attack-external-id-2035)|ALERT_EXTERNAL_AATP_ABNORMAL_SMB_WANNA_CRY_SECURITY_ALERT|
> |[Suspicious additions to sensitive groups](domain-dominance-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024)|ALERT_EXTERNAL_AATP_ABNORMAL_SENSITIVE_GROUP_MEMBERSHIP_CHANGE_SECURITY_ALERT|
> |[Suspicious communication over DNS](exfiltration-alerts.md#suspicious-communication-over-dns-external-id-2031)|ALERT_EXTERNAL_AATP_DNS_SUSPICIOUS_COMMUNICATION_SECURITY_ALERT|
> |[Suspicious service creation](domain-dominance-alerts.md#suspicious-service-creation-external-id-2026)|ALERT_EXTERNAL_AATP_MALICIOUS_SERVICE_CREATION_SECURITY_ALERT|
> |[Suspicious VPN connection](compromised-credentials-alerts.md#suspicious-vpn-connection-external-id-2025)|ALERT_EXTERNAL_AATP_ABNORMAL_VPN_SECURITY_ALERT|
> |[User and Group membership reconnaissance (SAMR)](reconnaissance-alerts.md#user-and-group-membership-reconnaissance-samr-external-id-2021)|ALERT_EXTERNAL_AATP_SAMR_RECONNAISSANCE_SECURITY_ALERT|
> |[User and IP address reconnaissance (SMB)](reconnaissance-alerts.md#user-and-ip-address-reconnaissance-smb-external-id-2012)|ALERT_EXTERNAL_AATP_ENUMERATE_SESSIONS_SECURITY_ALERT|

<!-- FROM TOP TABLE |[Suspected over-pass-the-hash attack (encryption downgrade)](lateral-movement-alerts.md#suspected-overpass-the-hash-attack-encryption-downgrade-external-id-2008)|2008|Medium|Lateral movement|-->
<!-- FROM BOTTOM TABLE |[Suspected over-pass-the-hash attack (encryption downgrade)](lateral-movement-alerts.md#suspected-overpass-the-hash-attack-encryption-downgrade-external-id-2008)|ALERT_EXTERNAL_AATP_OVERPASS_THE_HASH_ENCRYPTION_DOWNGRADE_SECURITY_ALERT|-->

---

> [!NOTE]
> To disable any security alert, contact support.

## See Also

- [Working with security alerts](working-with-suspicious-activities.md)
- [Understanding security alerts](understanding-security-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
