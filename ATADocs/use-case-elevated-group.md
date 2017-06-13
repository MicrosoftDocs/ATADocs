---
# required metadata

title: Investigating Forged PAC attacks | Microsoft Docs
description: This article describes the Forged PAC attack and provides investigation instructions when this threat is detected on your network.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 6/12/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 8b164cc7-189e-4d45-b2eb-cbadb1071d85

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Advanced Threat Analytics version 1.8*

# Investigating elevated group modifications

ATA keeps tabs on elevated groups in your network. The following elevated groups and any groups nested within them are specifically monitored:
- Enterprise Read Only Domain Controllers 
- Domain Admins 
- Domain Controllers 
- Schema Admins,
- Enterprise Admins 
- Group Policy Creator Owners 
- Read Only Domain Controllers 
- Administrators  
- Power Users  
- Account Operators  
- Server Operators   
- Print Operators,
- Backup Operators,
- Replicators 
- Remote Desktop Users 
- Network Configuration Operators 
- Incoming Forest Trust Builders 
- DNS Admins 


For each of these groups, ATA profiles any changes made. ATA has a learning period during which it profiles groups - who makes changes, how often changes are made, etc. so when someone unusual makes a change or rapid changes are made, ATA will alert about it. For example, if an IT admin adds and removes people from the sensitive groups ATA will recognized this change, but not flag it as suspicious, but if a non-admin user makes a change to one of these groups, because this activity is unusual ATA raises an alert.


This detection is based on event forwarding - the learning period starts after event forwarding is configured.


## Why are elevated group modifications a threat?





## Discovering the attack


## Investigating



## See Also
- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Modifying ATA configuration](modifying-ata-configuration.md)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
