---
title: What is Microsoft Advanced Threat Analytics (ATA)? | Microsoft Advanced Threat Analytics
ms.custom:
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology:
  - security
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid:
author: Rkarlin
---

## What is ATA?
Microsoft Advanced Threat Analytics (ATA) is a security solution that helps IT security professionals protect their organization from advanced targeted attacks and insider threats. By automatically analyzing, learning, and identifying normal and abnormal entity (user, devices, and resources) behavior, ATA helps identify known malicious attacks and techniques, security issues, and risks. Using world-class security researcher intelligence and insight, this innovative technology is designed to help enterprises focus on identifying security breaches before they cause damage.

## What does ATA do?
ATA detects:

  - Advanced persistent threats (APTs) early in the attack kill-chain, before they cause damage

  - Insider threats
  
  ATA also allows you to separate the signal from the noise to focus on what is critical.
  
ATA’s detection engine leverages machine learning, entity-contextual deep packet inspection, log analysis, and information from Active Directory (AD) to analyze user and entity behavior. 
ATA runs deep analysis on your organization's traffic, and leverages machine learning to build a map of what normal activities, traffic and use look like in your organization. Then, ATA watches for and notifies you when abnormal things happen. This is accomplished by running Microsoft's deep packet inspection technology (DPI), which enables entity-contextual packet inspection for a deeper level of network traffic parsing, enabling ATA to analyze all levels of your network traffic. 
ATA also collects relevant events from SIEM systems and Domain Controllers. After analysis, ATA builds a dynamic, continuously-updated view of all the people, devices, and resources within an organization. Using this comprehensive view, ATA is able to detect known malicious attacks such as pass-the-hash, pass-the-ticket, reconnaissance attacks and others as well as look for any abnormalities in the behavior of entities on your network.  
Once a suspicious activity is detected, ATA raises an alert--minimizing the number of false positives you receive by using advanced algorithms for aggregation and context verification.




## What threats does ATA look for?

ATA provides detection for the following various phases of an advanced attack: reconnaissance, credential compromise, lateral movement, privilege escalation, domain dominance and others. These detections are aimed at detecting advanced attacks and insider threats before they cause damage to your organization. 
The detection of each phase results in several suspicious activities relevant for the phase in question, where each suspicious activity correlates to different flavors of possible attacks. 


### Reconnaissance
ATA provides multiple reconnaissance detections. For example, the suspicious activity **Reconnaissance using account enumeration** detects attempts by attackers using the Kerberos protocol to discover if a users exists, even if the activity was not logged as an event on the domain controller.

### Credential comporomise

To provide detection of compromised credentials, ATA leverages both machine-learning based behavioral analytics as well as known malicious attacks and technique detection.  
Using behavioral analytics and machine learning, ATA is able to detect suspicious activities such as anomalous logins, abnormal resource access, and abnormal working hours which would point to credential compromise. 
To protect agains comproimised credentials, ATA detects the following known malicious attacks and techniques:
 - Brute force
	In brute-force attacks, attackers try guess user credentials by trying multiple users and pairing them with multiple password attempts, often using complex algorithms or dictionaries to try as many values as a system allows.
    
- Sensitive account exposed in plain text authentication
	If high privileged account credentials are sent in plain text, ATA alerts you so that you can update the computer's configuration.
- Service exposing accounts in plain text authentication
	If a service on a computer is sending multiple account credentials in plain text, ATA alerts you so that you can update the service's configuration.
- Honey Token account suspicious activities
Honey Token accounts are dummy accounts set up for the purpose of trapping, identifying and tracking malicious activity that attempts to use these dummy accounts.

### Lateral movement
To provide detection of lateral movement, when users take advantage of credentials that provide access to some resources to gain access resources that they are not meant to have access to, ATA leverages both machine-learning based behavioral analytics as well as known malicious attacks and technique detection.  
Using behavioral analytics and machine learning, ATA detects abnormal resource access, abnormal devices used and other indicators that are evidence of lateral movement.
In addition, ATA is able to detect lateral movement by detecting the techniques used by attackers to perform lateral movement, such as:
- Pass the ticket
	In pass the ticket attacks, attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by impersonating an entity on your network.
- Pass the hash
	In pass the hash attacks, attackers steal the NTLM hash of an entity, and use it to authenticate with NTLM and impersonate the entity and gain access to resources on your network.
- Over-pass the hash
	Over-pass the hash are attacks in which the attacker uses a stolen NTLM hash to authenticate with Kerberos, and obtain a valid Kerberos TGT ticket which is then used to authenticate as a valid user and gain access to resources on your network.

### Privilege escalation 
ATA detects successful and attempted privilege escalation attacks, in which attackers attempt to increase existing privileges and use them multiple times in order to eventually gain full control over the victim’s environment. ATA enables privilege escalation detection by combining behavioral analytics to detect anomalous behavior of privileged accounts as well as detecting known and malicious attacks and techniques that are often used to escalate privileges such as:
- MS14-068 exploit (Forged PAC)
	Forged PAC are attacks in which the attacker plants authorization data in their valid TGT ticket in the form of a forged authorization header that grants them additional permissions that they weren't granted by their organization.
    - The use of previously compromised credentials, or credentials harvested during lateral movement operations.
### Domain dominance
ATA detects attackers attempting or successfully achieving total control and dominance over the victim’s environment by performing detection over known techniques used by attackers, which include:
- Skeleton key malware
	 In skeleton key attacks, malware is installed on your domain controller that allows attackers to authenticate as any user, while still enabling legitimate users to log on.
- Golden ticket
	 In golden ticket attacks, an attacker steals the KBTGT's credentials, the Kerberos Golden Ticket, which enables the attacker to create a TGT ticket offline, to be used to gain access to resources in the network.
- Remote execution
	 Attackers can attempt to control your network by running code remotely on your domain controller.


## What next?

-   For more information about how ATA fits into your network check out: [ATA architecture](ata-architecture.md)

-   To get started deploying ATA: [Install ATA](/ATA/DeployUse/install-ata.html)

## See Also
[For ATA support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
