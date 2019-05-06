---
# required metadata

title: Azure ATP monitored domain activities | Microsoft Docs
description: Describes each activity type monitored by Azure Advanced Threat Protection
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 1/13/2018
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 37d1a032-65e7-4a89-be0b-c3f9cc2bacdb

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---



# Azure ATP monitored activities

Azure Advanced Threat Protection monitors information generated from your organization's Active Directory, network activities and event activities to detect suspicious activity. The monitored activity information enables Azure ATP to help you determine the validity of each potential threat and correctly triage and respond. 

In the case of a valid threat, or **true positive**, Azure ATP enables you to discover the scope of breach for each incident, investigate which entities are involved, and determine how to remediate them.

The information monitored by Azure ATP is presented in the form of activities. Azure ATP currently supports monitoring of the following activity types:

> [!NOTE] 
> - This article is relevant for all Azure ATP sensor types.
>- Azure ATP monitored activities appear on both the user and machine profile page. 
 

## Monitored user activities: User account AD attribute changes

|Monitored activity|Description|
|---------------------|------------------|
|Account Constrained Delegation State Changed |The account state is now enabled or disabled for delegation.|
|Account Constrained Delegation Spns Changed | Constrained delegation restricts the services to which the specified server can act on behalf of the user.|
|Account Disabled Changed |Indicates whether an account is disabled or enabled.|
|Account Expired|Date when the account expires.|
|Account Expiry Time Changed |Change to the date when the account expires.|
|Account Locked Changed|Change to the date when the account expires.|
|Account Password Changed|User changed their password.|
|Account Password Expired |User's password expired.|
|Account Password Never Expires Changed |User's password changed to never expire.|
|Account Password Not Required Changed |User account was changed allow logging in with a blank password.|
|Account Smartcard Required Changed  |Account changes to require users to log on to a device using a smart card.|
|Account Supported Encryption Types Changed |Kerberos supported encryption types were changed (types: Des, AES 129, AES 256)|
|Account Upn Name Changed  |User's principle name was changed.|
|Group Membership Changed  |User was added/removed, to/from a group, by another user or by themselves.|
|User Mail Changed|Users email attribute was changed.|
|User Manager Changed|User's manager attribute was changed.|
|User Phone Number Changed|User's phone number attribute was changed.|
|User Title Changed |User's title attribute was changed.|

## Monitored user activities: AD security principal operations

|Monitored activity|Description|
|---------------------|------------------|
|Security Principal Created |Account was created (both user and computer).|
|Security Principal Deleted Changed  |Account was deleted/restored (both user and computer).|
|Security Principal Display Name Changed   |Account display name was changed from X to Y.|
|Security Principal Name Changed  |Account name attribute was changed.|
|Security Principal Path Changed  |Account Distinguished name was changed from X to Y.|
|Security Principal Sam Name Changed |SAM name changed (SAM is the logon name used to support clients and servers running earlier versions of the operating system).|

## Monitored user activities: Domain controller based user operations

|Monitored activity|Description|
|---------------------|------------------|
|Directory Service Replication  |Used tried to replicate the directory service.|
|DNS Query  |Type of query user performed against the domain controller (**AXFR**,**TXT**, **MX**, **NS**, **SRV**, **ANY**, **DNSKEY**).|
|Private Data Retrieval  |User attempted/succeeded to query private data using LSARPC protocol.|
|Service Creation   |User attempted to remotely create a specific service to a remote machine.|
|SMB Session Enumeration   |User attempted to enumerate all users with open SMB sessions on the domain controllers.|
|SMB file copy| User copied files using SMB|
|SAMR Query   |User performed a SAMR query.|
|Task Scheduling  |User tried to remotely schedule X task to a remote machine.|
|Wmi Execution  |User attempted to remotely execute a WMI method.|

## Monitored user activities: Login operations

|Logon type|Monitored activity|Description|
|---------------------|---------------------|------------------|
|Logon type 2|Credentials Validation  |Domain-account authentication event using the NTLM and Kerberos authentication methods.|
|Logon type 2|Interactive Logon  |User gained network access by entering a username and password (authentication method Kerberos).|
|Logon type 2|VPN Connection   |User connected by VPN - Authentication using RADIUS protocol.|
|Logon type 3|Resource Access  |User accessed a resource using Kerberos authentication.|
|Logon type 8|LDAP Cleartext  |User authenticated using LDAP with a clear-text password (Simple authentication).|
|Logon type 10|Remote Desktop |User performed an RDP session to a remote computer using Kerberos authentication.|
| --- |Failed Logon |Domain-account failed authentication attempt (via NTLM and Kerberos) due to the following: account was disabled/expired/locked/used an untrusted certificate or due to invalid logon hours/old password/expired password/wrong password.|


## Monitored machine activities: Machine account

|Monitored activity|Description|
|---------------------|------------------|
|Computer Operating System Changed|Change to the computer OS.


## See Also
- [Managing security alerts](working-with-suspicious-activities.md)
- [Security alert guide](suspicious-activity-guide.md)
- [Investigate entities](investigate-entity.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
