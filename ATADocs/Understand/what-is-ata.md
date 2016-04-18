---
# required metadata

title: What is Microsoft Advanced Threat Analytics (ATA)? | Microsoft Advanced Threat Analytics
description: Explains what Microsoft Advanced Threat Analytics (ATA) is and what kinds of suspicious activities it can detect
keywords:
author: rkarlin
manager: stevenpo
ms.date: 04/28/2016
ms.topic: article
ms.prod: identity-ata
ms.service: advanced-threat-analytics
ms.technology: security
ms.assetid: 283e7b4e-996a-4491-b7f6-ff06e73790d2

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---


## What is ATA?
Microsoft Advanced Threat Analytics (ATA) is a security solution that helps IT security professionals protect their organization from advanced targeted attacks and insider threats. ATA automatically analyzes, learns, and identifies normal and abnormal entity (users, devices, and resources) behavior to identify risks such as known malicious attacks and techniques and security issues. Using world-class security researcher intelligence and insight, this innovative technology is designed to help enterprises focus on identifying security breaches before they cause damage.

## What does ATA do?
ATA detects:

  - Advanced persistent threats (APTs) early in the attack kill-chain, before they cause damage

  - Insider threats

  ATA also allows you to separate the signal from the noise to focus on what is critical.

ATA has a detection engine that leverages machine learning, entity-contextual deep packet inspection, log analysis, and information from Active Directory (AD) to analyze user and entity behavior.
This detection engine performs deep analysis on traffic and uses machine learning to build a map of what normal activities, traffic, and use look like in your organization. Then, ATA watches for and notifies you when abnormal things happen. This result is accomplished by running Microsoft's deep packet inspection technology (DPI). This technology enables entity-contextual packet inspection for a deeper level of network traffic parsing, enabling ATA to analyze all levels of your network traffic. ATA also collects relevant events from SIEM systems and Domain Controllers. 

After analysis, ATA builds a dynamic, continuously updated view of all people, devices, and resources within an organization. Using this comprehensive view, ATA is able to detect known malicious attacks such as pass-the-hash, pass-the-ticket and reconnaissance attacks. ATA also looks for any abnormalities in the behavior of entities on your network.  

Once a suspicious activity is detected, ATA raises an alert, minimizing the number of false positives you receive by using advanced algorithms for aggregation and context verification.


## What threats does ATA look for?

ATA provides detection for the following various phases of an advanced attack: reconnaissance, credential compromise, lateral movement, privilege escalation, domain dominance, and others. These detections are aimed at detecting advanced attacks and insider threats before they harm your organization.

The detection in each phase searches for several suspicious activity types relevant for the phase in question. Each suspicious activity correlates to different flavors of possible attacks.


### Reconnaissance
ATA provides multiple reconnaissance detections. For example, the suspicious activity **Reconnaissance using account enumeration** detects attempts by attackers using the Kerberos protocol to discover if a user exists, even if the activity was not logged as an event on the domain controller.

### Credential compromise

ATA detects compromised credentials by leveraging both machine-learning based behavioral analytics as well as known malicious attacks and technique detection.  

ATA is able to detect suspicious activities such as anomalous logins, abnormal resource access, and abnormal working hours. Any of these suspicious activities indicate a potential credential compromise.

To protect against compromised credentials, ATA detects the following known malicious attacks and techniques:

 - **Brute force** - In brute-force attacks, attackers try to guess user credentials by trying multiple users and pairing them with multiple password attempts. The attackers often use complex algorithms or dictionaries to try as many values as a system allows.

- **Sensitive account exposed in plain text authentication** - If high-privileged account credentials are sent in plain text, ATA alerts you so that you can update the computer configuration.

- **Service exposing accounts in plain text authentication** - If a service on a computer is sending multiple account credentials in plain text, ATA alerts you so that you can update the service configuration.

- **Honey Token account suspicious activities** - Honey Token accounts are dummy accounts set up to trap, identify, and track malicious activity that attempts to use these dummy accounts. ATA alerts you to any activities across these Honey Tokens accounts.

### Lateral movement
Lateral movement occurs when users take advantage of credentials that provide access to some resources to gain access to other resources that they are not meant to access. ATA leverages both machine-learning based behavioral analytics as well as known malicious attacks and technique detection to identify such lateral movement.  

ATA detects abnormal resource access, when abnormal devices are used, and other indicators that are evidence of lateral movement. In addition, ATA is able to detect lateral movement by detecting the techniques used by attackers to perform lateral movement, such as:
- **Pass the ticket** - In pass the ticket attacks, attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by impersonating an entity on your network.
- **Pass the hash** - In pass the hash attacks, attackers steal the NTLM hash of an entity, and use it to authenticate with NTLM and impersonate that entity and gain access to resources on your network.
- **Over-pass the hash** - Over-pass the hash are attacks in which the attacker uses a stolen NTLM hash to authenticate with Kerberos, and obtain a valid Kerberos TGT ticket, which is then used to authenticate as a valid user and gain access to resources on your network.

### Privilege escalation
A privilege escalation attack occurs when attackers attempt to increase existing privileges and use them multiple times to eventually gain full control over the victim’s environment. ATA detects both successful and attempted privilege escalation attacks. ATA uses behavioral analytics to detect anomalous behavior of privileged accounts. ATA also detects known malicious attacks and techniques that are often used to escalate privileges such as:
- **MS14-068 exploit (Forged PAC)** - Forged PAC are attacks in which the attacker plants authorization data in their valid TGT ticket in the form of a forged authorization header. With this technique, the attacker obtains permissions that they weren't granted by their organization.
- The use of previously compromised credentials, or credentials harvested during lateral movement operations.

### Domain dominance
Domain dominance occurs when attackers attempt or succeed at achieving total control and dominance over the environment of the victim. ATA detects these attempts by looking for known techniques used by attackers, which include:
- **Skeleton key malware** - In skeleton key attacks, malware is installed on your domain controller that allows attackers to authenticate as any user, while still enabling legitimate users to log on.
- **Golden ticket** - In golden ticket attacks, an attacker steals the KBTGT's credentials, the Kerberos Golden Ticket. That ticket enables the attacker to create a TGT ticket offline, to be used to gain access to resources in the network.
- **Remote execution** - Attackers can attempt to control your network by running code remotely on your domain controller.


## What's next?

-   For more information about how ATA fits into your network: [ATA architecture](ata-architecture.md)

-   To get started deploying ATA: [Install ATA](/advanced-threat-analytics/DeployUse/install-ata)

## See Also
[For ATA support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
