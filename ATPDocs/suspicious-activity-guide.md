---
# required metadata

title: Azure ATP security alert guide | Microsoft Docs
d|Description: This article provides a list of the security alerts issued by Azure ATP.
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 1/13/2019
ms.topic: conceptual
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
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

*Applies to: Azure Advanced Threat Protection*

# Azure ATP Security Alerts

## Security alert name mapping and unique external IDs

In version 2.56, all existing Azure ATP security alerts were renamed with easier to understand names. Mapping between old and new names, and their corresponding unique externalIds are as listed in the following table. Microsoft recommends use of alert external IDs in place of alert names for scripts or automation as only security alert external IDs are permanent and not subject to change.

> [!div class="mx-tableFixed"] 

|New security alert name|Previous security alert name|Unique external ID|
|---------|----------|---------|
|Account enumeration reconnaissance|Reconnaissance using account enumeration|2003|
|Data exfiltration over SMB| NA| 2030|
|Honeytoken activity|Honeytoken activity|2014|
|Malicious request of Data Protection API master key|Malicious Data Protection Private Information Request|2020|
|Network mapping reconnaissance (DNS)|Reconnaissance using DNS|2007|
|Remote code execution attempt|Remote code execution attempt|2019|
|Suspected brute force attack (LDAP)|Brute force attack using LDAP simple bind|2004|
|Suspected brute force attack (Kerberos, NTLM)|Suspicious authentication failures|2023|
|Suspected brute force attack (SMB)|Unusual protocol implementation (potential use of malicious tools such as Hydra)|2033|
|Suspected DCShadow attack (domain controller promotion)|Suspicious domain controller promotion (potential DCShadow attack)|2028|
|Suspected DCShadow attack (domain controller replication request)|Suspicious domain controller replication request (potential DCShadow attack)|2029|
|Suspected DCSync attack (replication of directory services)|Malicious replication of directory services|2006|
|Suspected Golden Ticket usage (encryption downgrade)|Encryption downgrade activity (potential golden ticket attack)|2009|
|Suspected Golden Ticket usage (forged authorization data) |Privilege escalation using forged authorization data|2013|
|Suspected Golden Ticket usage (nonexistent account)|Kerberos Golden Ticket - nonexistent account|2027|
|Suspected Golden Ticket usage (time anomaly) |Kerberos Golden Ticket - time anomaly|2022|
|Suspected Golden Ticket usage (ticket anomaly) - preview|NA|2032|
|Suspected identity theft (pass-the-hash)|Identity theft using Pass-the-Hash attack|2017|
|Suspected identity theft (pass-the-ticket)|Identity theft using Pass-the-Ticket attack|2018|
|Suspected over-pass-the-hash attack (encryption downgrade)|Encryption downgrade activity (potential overpass-the-hash attack)|2008|
|Suspected overpass-the-hash attack (Kerberos)|Unusual Kerberos protocol implementation (potential overpass-the-hash attack)|2002|
|Suspected use of Metasploit hacking framework|Unusual protocol implementation (potential use of Metasploit hacking tools)|2034|
|Suspected skeleton key attack (encryption downgrade)|Encryption downgrade activity (potential skeleton key attack)|2010|
|Suspected WannaCry ransomware attack|Unusual protocol implementation (potential WannaCry ransomware attack)|2035|
|Suspicious communication over DNS|Suspicious communication over DNS|2031|
|Suspicious modification of sensitive groups|Suspicious modification of sensitive groups|2024|
|Suspicious service creation|Suspicious service creation|2026|
|Suspicious VPN connection|Suspicious VPN connection|2025|
|User and group membership reconnaissance (SAMR)|Reconnaissance using directory services queries|2021|
|User and IP address reconnaissance (SMB) |Reconnaissance using SMB Session Enumeration|2012|


Azure ATP security alerts are divided into the following categories or phases, like the phases seen in a typical cyber-attack kill chain. Learn more about each phase, the alerts designed to detect each attack, and how to use the alerts to help protect your network using the following links:

*Phases:*
    [1. Reconnaissance alerts](atp-reconnaissance-alerts.md)
   <br>[2. Compromised credential alerts](atp-compromised-credentials-alerts.md)
   <br>[3. Lateral movement alerts](atp-lateral-movement-alerts.md)
   <br>[4. Domain dominance alerts](atp-domain-dominance-alerts.md)
   <br>[5. Exfiltration alerts](atp-exfiltration-alerts.md)

> [!NOTE]
> To disable any security alert, contact support.


## See Also
- [Working with security alerts](working-with-suspicious-activities.md)
- [Understanding security alerts](understanding-security-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
