---
# required metadata

title: Azure ATP SIEM log reference | Microsoft Docs 
description: Provides samples of suspicious activity logs sent from Azure ATP to your SIEM. 
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 8/06/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 3261155c-3c72-4327-ba29-c113c63a4e6d

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: arzinger

ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*


# Azure ATP SIEM log reference

Azure ATP can forward suspicious activity and monitoring alert events to your SIEM. Suspicious activity events are in the CEF format. This reference article provides samples of the suspicious activity logs sent to your SIEM.

## Sample Azure ATP suspicious activities in CEF format
The following fields and their values are forwarded to your SIEM:

-	start – the start time of the alert
-	suser – the account (usually should be user account) that is involved in this alert
-	shost – the source machine for this alert
-	outcome – for alerts where there is a success/failure of the activity performed in that alert  
-	msg – the description for the alert
-	cnt – for alerts that have a count of times that alert happened (for example brute force that has an amount of guessed passwords)
-	app – the protocol used in this alert
-	externalId – the event ID Azure ATP writes to the event log that corresponds to this alert
-	cs#label & cs# – these are the customer strings that CEF allows to use, the cs#label is the name of the new field and cs# is the value, for example:
cs1Label=url cs1=https://192.168.0.220/suspiciousActivity/5909ae198ca1ec04d05e65fa

In this example, cs1 is a field that has a URL to the alert.

## Sample logs

The following logs example comply with RFC 5242, but Azure ATP also supports RFC 3164.

Priorities:

- 3=Low
- 5=Medium
- 10=High

### BruteForce – LDAP
02-21-2018	16:20:21	Auth.Warning	192.168.0.220	1 2018-02-21T14:20:06.156238+00:00 CENTER CEF 6076 LdapBruteForceSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|LdapBruteForceSecurityAlert|Brute force attack using LDAP simple bind|5|start=2018-02-21T14:19:41.7422810Z app=Ldap suser=Wofford Thurston shost=CLIENT1 msg=A brute force attack using the Ldap protocol was attempted on Wofford Thurston (Software Engineer) from CLIENT1 (100 guess attempts). cnt=100 externalId=2004 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/57b8ac96-7907-4971-9b27-ec77ad8c029a


### BruteForce
02-21-2018	16:19:20	Auth.Warning	192.168.0.220	1 2018-02-21T14:19:15.397995+00:00 CENTER CEF 6076 BruteForceSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|BruteForceSecurityAlert|Suspicious authentication failures|5|start=2018-02-21T14:19:03.3831122Z app=Kerberos shost=CLIENT1 msg=Suspicious authentication failures indicating a potential brute-force attack were detected from CLIENT1. externalId=2023 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/fea88fc7-4110-454d-816d-349032474fd6
### Privilege escalation
#### Silver
02-21-2018	16:19:20	Auth.Error	192.168.0.220	1 2018-02-21T14:19:15.186167+00:00 CENTER CEF 6076 ForgedPacSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|ForgedPacSecurityAlert|Privilege escalation using forged authorization data|10|start=2018-02-21T14:19:02.8595383Z app=Kerberos suser=user1 msg=user1 attempted to escalate privileges to host/domain1.test.local from CLIENT1 by using forged authorization data. externalId=2013 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/029189e1-6bb4-490b-bcaf-5fac4457e9f3
#### Gold
02-21-2018	16:19:20	Auth.Error	192.168.0.220	1 2018-02-21T14:19:14.358037+00:00 CENTER CEF 6076 ForgedPacSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|ForgedPacSecurityAlert|Privilege escalation using forged authorization data|10|start=2018-02-21T14:19:02.8595383Z app=Kerberos suser=user1 msg=user1 failed to escalate privileges against DC1 to host/domain1.test.local from CLIENT1 by using forged authorization data. externalId=2013 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/f3359eff-cb59-44b9-82b6-5e82ff06e6c8
### Golden Ticket
02-21-2018	16:22:39	Auth.Error	192.168.0.220	1 2018-02-21T14:22:34.274054+00:00 CENTER CEF 6076 GoldenTicketSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|GoldenTicketSecurityAlert|Kerberos Golden Ticket activity|10|start=2018-02-21T14:19:03.2416152Z app=Kerberos suser=Lanell Campos msg=Suspicious usage of Lanell Campos (Software Engineer)'s Kerberos ticket, indicating a potential Golden Ticket attack, was detected. externalId=2022 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/702c836e-6f49-4479-9892-80e8bccbfac0
### Kerberos Golden Ticket nonexistent account
07-01-2018  14:28:49    Auth.Error  192.168.0.100   1 2018-07-01T11:28:35.546638+00:00 CENTER CEF 38768 ForgedPrincipalSecurityAlert ï»¿0|Microsoft|Azure ATP|2.39.0.0|ForgedPrincipalSecurityAlert|Kerberos Golden Ticket - non-existing account|10|start=2018-07-01T09:48:31.2567987Z app=Kerberos suser=domain1.test.local\fake msg=domain1.test.local\fake, which does not exist in Active Directory, used a Kerberos ticket. The ticket was detected from 2 computers to access 3 resources. This may indicate a potential Golden Ticket attack. externalId=2027 cs1Label=url cs1=https://contoso-corp.atp.azure.com:13000/securityAlert/98f050d4-9134-429c-8e54-d8eeb19849c4


### Honey Token Activity
02-21-2018	16:20:36	Auth.Warning  192.168.0.220	1 2018-02-21T14:20:34.106162+00:00 CENTER CEF 6076 HoneytokenActivitySecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|HoneytokenActivitySecurityAlert|Honeytoken activity|5|start=2018-02-21T14:20:26.6705617Z app=Kerberos suser=honey msg=The following activities were performed by honey:\r\nLogged in to CLIENT2 via DC1. externalId=2014 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/9249fe9a-c883-46dd-a4da-2a1fca5f211c
### Suspicious replication of directory services
02-21-2018	16:21:22	Auth.Error	192.168.0.220	1 2018-02-21T14:21:13.978554+00:00 CENTER CEF 6076 DirectoryServicesReplicationSecu ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|DirectoryServicesReplicationSecurityAlert|Malicious replication of directory services|10|start=2018-02-21T14:19:03.9975656Z app=Drsr shost=CLIENT1 msg=Malicious replication requests were successfully performed by user1, from CLIENT1 against DC1. outcome=Success externalId=2006 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/cb95648e-1b6f-4d3b-81b9-7605532787d7
### Suspicious replication request (potential DcShadow attack)
07-12-2018  11:18:37    Auth.Error  192.168.0.200    1 2018-07-12T08:18:32.265989+00:00 DC1 CEF 3868 DirectoryServicesRogueReplicatio ï»¿0|Microsoft|Azure ATP|2.40.0.0|DirectoryServicesRogueReplicationSecurityAlert|[PREVIEW] **Suspicious replication request (potential DcShadow attack)**|10|start=2018-07-12T08:17:55.3816102Z **app=Replication Activity** shost=CLIENT1 msg=CLIENT1, which is not a valid domain controller in domain1.test.local, sent changes to directory objects on DC1. externalId=2029 cs1Label=url cs1=https://contoso-corp.atp.azure.com:13000/securityAlert/1d5d1444-12cf-4db9-be48-39ebc2f51515
### Suspicious domain controller promotion (potential DcShadow attack)
07-12-2018  11:18:07    Auth.Error  192.168.0.200    1 2018-07-12T08:18:06.883880+00:00 DC1 CEF 3868 DirectoryServicesRoguePromotionS ï»¿0|Microsoft|Azure ATP|2.40.0.0|DirectoryServicesRoguePromotionSecurityAlert|[PREVIEW] **Suspicious domain controller promotion (potential DcShadow attack)**|10|start=2018-07-12T08:17:55.4067092Z app=Ldap shost=CLIENT1 msg=CLIENT1, which is a computer in domain1.test.local, registered as a domain controller on DC1. externalId=2028 cs1Label=url cs1=https://contoso-corp.atp.azure.com:13000/securityAlert/97c59b43-dc18-44ee-9826-8fd5d03bd53

### Malicious Data Protection Private Information Request
02-21-2018	16:22:08	Auth.Error	192.168.0.220	1 2018-02-21T14:21:54.080266+00:00 CENTER CEF 6076 RetrieveDataProtectionBackupKeyS ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|RetrieveDataProtectionBackupKeySecurityAlert|Malicious Data Protection Private Information Request|10|start=2018-02-21T14:19:41.8382786Z app=LsaRpc shost=CLIENT1 msg=user1 performed 1 successful attempts from CLIENT1 to retrieve DPAPI domain backup key from DC1. externalId=2020 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/b22221d1-764a-4fae-a5ce-e6a0c69dc55a

### Over-pass-the-hash
02-21-2018	16:21:07	Auth.Warning	192.168.0.220	1 2018-02-21T14:20:54.145833+00:00 CENTER CEF 6076 EncryptionDowngradeSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|EncryptionDowngradeSecurityAlert|Encryption downgrade activity|5|start=2018-02-21T14:19:41.8737870Z app=Kerberos msg= The encryption method of the Encrypted_Timestamp field of AS_REQ message from CLIENT1 has been downgraded based on previously learned behavior. This may be a result of a credential theft using Overpass-the-Hash from CLIENT1. externalId=2011 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/6354b9ed-6a39-4f5b-b10e-f51bbee879d2
### Pass-the-hash
02-21-2018	17:04:47	Auth.Error	192.168.0.220	1 2018-02-21T15:04:33.537583+00:00 CENTER CEF 6076 PassTheHashSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|PassTheHashSecurityAlert|Identity theft using Pass-the-Hash attack|10|start=2018-02-21T15:02:22.2577465Z app=Kerberos suser=Eugene Jenkins msg=Eugene Jenkins (Software Engineer)'s hash was stolen from one of the computers previously logged into by Eugene Jenkins (Software Engineer) and used from CLIENT1. externalId=2017 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/511f1487-2915-477d-be2e-04cfba702ccd
### Account enumeration
02-21-2018	16:19:35	Auth.Warning	192.168.0.220	1 2018-02-21T14:19:27.540731+00:00 CENTER CEF 6076 AccountEnumerationSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|AccountEnumerationSecurityAlert|Reconnaissance using account enumeration|5|start=2018-02-21T14:19:02.6045416Z app=Kerberos shost=CLIENT1 suser=LMaldonado msg=Suspicious account enumeration activity using the Kerberos protocol, originating from CLIENT1, was observed and successfully guessed Lamon Maldonado (Software Engineer). externalId=2003 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/eb6a35da-ff7f-4ab5-a1b5-a07529a89e6d
### DNS Recon
02-21-2018	16:20:06	Auth.Warning	192.168.0.220	1 2018-02-21T14:19:54.063994+00:00 CENTER CEF 6076 DnsReconnaissanceSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|DnsReconnaissanceSecurityAlert|Reconnaissance using DNS|5|start=2018-02-21T14:19:41.9417776Z app=Dns shost=CLIENT1 request=demo query requestMethod=Axfr reason=NoError outcome=Success msg=Suspicious DNS activity was observed, originating from CLIENT1 (which is not a DNS server). The query was for demo query (type Axfr). The response was NoError. externalId=2007 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/6f69e1e7-304a-4054-8edf-33f26c1f004c


### SMB Session enumeration
02-21-2018	16:21:22	Auth.Warning	192.168.0.220	1 2018-02-21T14:21:13.962930+00:00 CENTER CEF 6076 EnumerateSessionsSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|EnumerateSessionsSecurityAlert|Reconnaissance using SMB Session Enumeration|5|start=2018-02-21T14:19:03.2071170Z app=SrvSvc shost=CLIENT1 msg=SMB session enumeration attempts were successfully performed by user1, from CLIENT1 against DC1, exposing Eugene Jenkins (user2-computer). externalId=2012 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/622c38ab-324f-4c1f-9caa-1fe85db3b440
### SAM-R enumeration
02-21-2018	16:22:08	Auth.Warning	192.168.0.220	1 2018-02-21T14:21:54.267658+00:00 CENTER CEF 6076 SamrReconnaissanceSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|SamrReconnaissanceSecurityAlert| Reconnaissance using directory services enumeration |5|start=2018-02-21T14:19:41.9912772Z app= Samr shost=CLIENT1 suser=user1 outcome=Success msg= The following directory services enumerations using SAMR protocol were attempted against DC1 from CLIENT1:\r\nSuccessful enumeration of all groups in domain1.test.local by user1. externalId=2019 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/f295029a-ffae-408b-9dd0-55424c81eac0
### Remote Execution
02-21-2018	16:22:08	Auth.Warning	192.168.0.220	1 2018-02-21T14:21:54.267658+00:00 CENTER CEF 6076 RemoteExecutionSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|RemoteExecutionSecurityAlert|Remote execution attempt detected|5|start=2018-02-21T14:19:41.9912772Z app=Wmi shost=CLIENT1 suser=user1 outcome=Success msg=The following remote execution attempts were performed on DC1 from CLIENT1:\r\nSuccessful remote execution of one or more WMI methods by user1. externalId=2019 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/f295029a-ffae-408b-9dd0-55424c81eac0
### Skeleton Key
02-21-2018	16:21:07	Auth.Warning	192.168.0.220	1 2018-02-21T14:20:54.145833+00:00 CENTER CEF 6076 EncryptionDowngradeSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|EncryptionDowngradeSecurityAlert|Encryption downgrade activity|5|start=2018-02-21T14:19:41.8737870Z app=Kerberos msg=The encryption method of the ETYPE_INFO2 field of KRB_ERR message from CLIENT1 has been downgraded based on previously learned behavior. This may be a result of a Skeleton Key on DC1. externalId=2011 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/6354b9ed-6a39-4f5b-b10e-f51bbee879d2

### Unusual protocol implementation
02-21-2018	16:21:22	Auth.Warning	192.168.0.220	1 2018-02-21T14:21:13.916050+00:00 CENTER CEF 6076 AbnormalProtocolSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|AbnormalProtocolSecurityAlert|Unusual protocol implementation|5|start=2018-02-21T14:19:03.1981155Z app=Ntlm shost=CLIENT2 outcome=Success msg=There were attempts to authenticate from CLIENT2 against DC1 using an unusual protocol implementation. This may be a result of malicious tools used to execute attacks such as Pass-the-Hash and brute force. externalId=2002 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/40fe98dd-aa42-4540-9d73-831486fdd1e4 cs1=https://192.168.0.220/suspiciousActivity/5909cce38ca1ec04d05f4ab4

### Malicious Service Creation
02-21-2018	16:20:06	Auth.Warning	192.168.0.220	1 2018-02-21T14:19:54.254930+00:00 CENTER CEF 6076 MaliciousServiceCreationSecurity ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|MaliciousServiceCreationSecurityAlert|Suspicious service creation|5|start=2018-02-21T14:19:41.7897808Z app=ServiceInstalledEvent shost=CLIENT1 msg=user1 created MaliciousService in order to execute potentially malicious commands on CLIENT1. externalId=2026 cs1Label=url cs1=https://contoso-corp.atp.azure.com/securityAlert/179229b6-b791-4895-b5aa-fdf3747a325c

### Pass the ticket
02-21-2018	17:04:47	Auth.Error	192.168.0.220	1 2018-02-21T15:04:33.537583+00:00 CENTER CEF 6076 PassTheTicketSecurityAlert ï»¿0|Microsoft|Azure ATP|2.22.4228.22540|PassTheTicketSecurityAlert|Identity theft using Pass-the-Ticket attack|10|start=2018-02-21T15:02:22.2577465Z app=Kerberos suser=Eugene Jenkins msg=Eugene Jenkins (Software Engineer)'s Kerberos tickets were stolen from Admin-PC to Victom-PC and used to access krbtgt/DOMAIN1.TEST.LOCAL. externalId=2017 cs1Label=url cs1=https://contoso-corp.eng.atp.azure.com/securityAlert/511f1487-2915-477d-be2e-04cfba702ccd


## See Also
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)