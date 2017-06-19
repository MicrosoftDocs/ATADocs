---
# required metadata

title: What's new in ATA version 1.8 | Microsoft Docs
description: Lists what was new in ATA version 1.8 along with known issues
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 6/18/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 9592d413-df0e-4cec-8e03-be1ae00ba5dc

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: 
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# What's new in ATA version 1.8
These release notes provide information about updates, new features, bug fixes and known issues in this version of Advanced Threat Analytics.

## New & updated detections
- NEW! **Abnormal modification of sensitive groups**  – As part of the privilege escalation phase, attackers modify groups with high privileges to gain access to sensitive resources. ATA now detects when there’s an abnormal change in an elevated group.
- NEW! **Suspicious authentication failures** (Behavioral brute force) – Attackers attempt to use brute force on credentials to compromise accounts. ATA now raises an alert when abnormal failed authentication behavior is detected.   
- NEW! **Remote execution attempt – WMI exec**  - Attackers can attempt to control your network by running code remotely on your domain controller. ATA added detection for remote execution leveraging WMI methods to run code remotely.
- Reconnaissance using directory service queries– In ATA 1.8, a machine learning algorithm was added to this detection allowing ATA to detect reconnaissance attempts against a single sensitive entity and improve the results for generic reconnaissance. 
- Kerberos Golden Ticket activity – ATA 1.8 includes an additional technique to detect golden ticket attacks.
- Enhancements were made to the following detections to remove known false positives:  
    - Privilege escalation detection  (forged PAC) 
    - Encryption downgrade activity (Skeleton Key)
    - Unusual protocol implementation
    - Broken trust

## Improved triage of suspicious activities

-	NEW! ATA 1.8 enables you to run the following actions suspicious activities during the triage process: 
    - **Exclude entities** from raising future suspicious activities to prevent ATA from alerting when it detects benign true positives (such as an admin running remote code or using nslookup).
    - **Suppress recurring** suspicious activities from alerting.
    - **Delete suspicious activities** from the attack time line.
-	The process for following up on suspicious activity alerts is now more efficient. The suspicious activities time line was redesigned. In ATA 1.8, you will be able to many more suspicious activities on a single screen, containing better information for triage and investigation purposes. 

- The Directory Service Enumeration feature was improved in version 1.8. If you disabled SAM-R as a result of version 1.7, installing version 1.8 will automatically enable it now that it functions properly.

- ATA now detects suspicious activities in which the Golden ticket lifetime has expired. If a Kerberos ticket is used for more than the allowed lifetime, ATA will detect it as a suspicious activity that a Golden ticket has likely been created.


## New reports to help you investigate 
-	NEW! The **Summary report** was added to enable you to see all the summarized data from ATA, including suspicious activities, health issues and more. You can even  define a customized report that is automatically generated on a recurring basis.
-	NEW! The **Sensitive groups report** was improved to enable you to see all the changes made in sensitive groups over a certain period.


## Infrastructure improvements

-	ATA Center performance was enhanced. In ATA 1.8 the ATA Center can handle more than 1M packets per second.
-	The ATA Lightweight Gateway can now read events locally, without the need to configure event forwarding.
-	Accessibility ramp up – ATA now stands with Microsoft in providing a product that is accessible to everyone. 
-	You can now separately configure email for monitoring alerts and suspicious activities.

## Security improvements

-	NEW! **Single-sign-on for ATA management**. Silent installation scripts for the ATA Gateway and ATA Lightweight Gateway now use the logged on user’s context, without the need to provide credentials.
-	Local System privileges were removed from the ATA Gateway process, so you can now use virtual accounts (available on stand-alone ATA Gateways only), managed service accounts and group managed service accounts to run the ATA Gateway process.   
-	Auditing logs for ATA Center and Gateways were added and all actions are now logged in the event viewer.
-	Support was added for KSP Certificates.




## See Also
[Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)

[Update ATA to version 1.7 - migration guide](ata-update-1.7-migration-guide.md)

