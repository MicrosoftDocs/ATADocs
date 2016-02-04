---
title: ATA FAQ
ms.custom: 
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology: 
  - security
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: e1954834-ff49-4ac1-b78c-06693569abff
author: Rkarlin
robots: noindex,nofollow
---
# ATA FAQ
This section provides answers to frequently asked questions about Microsoft Advanced Threat Analytics.

## What is Microsoft Advanced Threat Analytics?
Microsoft Advanced Threat Analytics (ATA) is an on-premises product to help IT security professionals protect their enterprise from advanced targeted attacks by automatically analyzing, learning, and identifying normal and abnormal entity (user, devices, and resources) behavior.  ATA also helps to identify known malicious attacks, security issues, and risks using world-class security researchers’ work regionally and globally. Leveraging user and entity behavioral analytics (UEBA), this innovative technology is designed to help enterprises focus on what is important and to identify security breaches before they cause damage.

## How does Microsoft Advanced Threat Analytics work?
Microsoft Advanced Threat Analytics uses Machine Learning for analyzing entity behavior. Using deep packet inspection technology, ATA analyzes all Active Directory network traffic. It can also collect relevant events from Security Information and Event Management (SIEM) systems or from Domain Controllers via Windows Event Forwarding and other resources (i.e. information in Active Directory). After analysis, ATA builds an Organizational Security Graph, a living, continuously-updated view of all the people, devices, and resources within an organization and understand what normal behavior is.  ATA can then look for any abnormalities in the entities’ behavior and raise red flags–but not before those abnormal activities have been contextually aggregated and verified.

One of the common complaints in IT security is the flood of security reports and false positives.  With this in mind, Microsoft Advanced Threat Analytics is designed to help IT focus on what is important in a simple and fast way. After detection of suspicious activities, ATA provides clear and relevant threat information on a simple attack timeline with recommendations for investigation and remediation.

## What does Microsoft Advanced Threat Analytics detect?
ATA is an on-premises product to help IT protect their enterprise from advanced targeted attacks by automatically analyzing, learning, and identifying normal and abnormal entity (user, devices, and resources) behavior.

-   **Abnormal user behavior**: Behavioral analytics leverage Machine Learning to uncover questionable activities and abnormal behavior.  (Anomalous logins, Unknown threats, Password sharing, Lateral movement).

-   **Malicious attacks**: ATA detects known malicious attacks almost as instantly as they occur. (Pass-the-Ticket, Pass-the-Hash, Overpass-the-Hash, Forged PAC (MS14-068), Remote execution, Golden Ticket, Skeleton key malware, Reconnaissance, Brute Force).

-   **Known security issues and risks**: ATA identifies known security issues using world-class security researchers’ work. (Broken trust, weak protocols, known protocol vulnerabilities).

## Is this an on-premises or in-cloud offering?
Microsoft Advanced Threat Analytics is an on-premises product.

## Is this going to be a part of Azure Active Directory or on-premises Active Directory?
This solution is currently a standalone offering—it is not a part of Azure Active Directory or on-premises Active Directory.

## Do you have to write your own rules and create a threshold/baseline?
With Microsoft Advanced Threat Analytics, there is no need to create rules, thresholds, or baselines and then fine-tune. ATA analyzes the behaviors among users, devices, and resources—as well as their relationship to one another—and can detect suspicious activity and known attacks fast. Three weeks after deployment, ATA starts to detect behavioral suspicious activities. On the other hand, ATA will start detecting known malicious attacks and security issues immediately after deployment.

## If you are already breached, will Microsoft Advanced Threat Analytics be able to identify abnormal behavior?
Yes, even when ATA is installed after you have been breached, ATA can still detect suspicious activities of the hacker. ATA is not only looking at the user’s behavior but also against the other users in the organization security map. During the initial analysis time, if the attacker’s behavior is abnormal, then it is identified as an “outlier” and ATA keeps reporting on the abnormal behavior. Additionally ATA can detect the suspicious activity if the hacker attempts to steal another users credentials, such as Pass-the-Ticket, or attempts to perform a remote execution on one of the domain controllers.

## Does this only leverage traffic from Active Directory?
In addition to analyzing Active Directory traffic using deep packet inspection technology, ATA can also collect relevant events from your Security Information and Event Management (SIEM) and create entity profiles based on information from Active Directory Domain Services. ATA can also collect events from the event logs if the organization configures Windows Event Log forwarding.

## What does Microsoft Advanced Threat Analytics access?
ATA requires port mirroring with the domain controllers to be able to perform deep packet inspection on the traffic to and from the domain controllers looking for known attacks.  ATA also uses the network traffic to learn which users are accessing which resources from which computers.

ATA also makes LDAP queries to the domain to fill in user and device profiles. The user account used by ATA only requires read-only access to the domain.

If you are collecting Windows Events to a central SIEM / Syslog server, ATA can be configured from these systems. This additional information source helps ATA in enriching the attack timeline.

## What is port mirroring?
Also known as SPAN (Switched Port Analyzer), port mirroring is a method of monitoring network traffic. With port mirroring enabled, the switch sends a copy of all network packets seen on one port (or an entire VLAN) to another port, where the packet can be analyzed.

## Does ATA monitor only domain-joined devices?
No. ATA monitors all devices in the network performing authentication and authorization requests against Active Directory, including non-Windows and mobile devices.

## Does ATA monitor computer accounts as well as user accounts?
Yes. Since computer accounts (as well as any other entities) can be used to perform malicious activities ATA monitors all computer accounts behavior and all other entities in the environment.

## Can ATA support multi-domain and multi-forest?
At general availability, Microsoft Advanced Threat Analytics will support multi-domain with the same forest boundary. The forest itself is the actual “security boundary”, so that providing multi-domain support will allow our customers to have 100% coverage of their environments with ATA.

## Can you see the overall health of the deployment?
Yes, you can view the overall health of the deployment as well as specific issues related to configuration, connectivity etc., and you will be alerted as they occur.

## What is Pass-the-Hash?
A Pass-the-Hash (PtH) attack uses a technique in which an attacker captures account logon credentials (specifically the NTLM hash) on one computer and then uses those captured credentials to authenticate from other computers in the network to access resources. A PtH attack is very similar in concept to a password theft attack, but it relies on stealing and reusing password hash values rather than the actual plaintext password. The password hash value, which is a one-way mathematical representation of a password, can be used directly as an authenticator to access services on behalf of the user through single sign-on (SSO) authentication.

For more information regarding Pass-the-Hash attacks, please read Mitigating Pass-the-Hash (PtH) attacks and other Credential Theft prepared by Microsoft Trustworthy Computing [here](http://www.microsoft.com/en-us/download/confirmation.aspx?id=36036)

## What is Pass the Ticket?
Pass the Ticket is a credential theft and reuse attack that resembles Pass-the-Hash attack in its execution steps, but involves the theft and re-use of a Ticket Granting Ticket (TGT) or a Ticket Granting Service (TGS) acquired by using the Kerberos protocol, rather than a NT Hash value and the NTLM protocol (which is used in Pass-The-Hash attacks).  Pass the Ticket (PtT) is an attack where the adversary steals a user’s Kerberos authentication ticket in order to impersonate that user against various enterprise resources.

The Kerberos authentication protocol enables the transparent Single Sign-On (SSO) experience. The SSO enables users to actively authenticate (i.e. provide their password) only once even though they access various services – whether in the corporate network or in the Cloud (whereas the Kerberos ticket is translated to SAML tokens).

The Kerberos Authentication protocol works in the following manner:

![](../Image/ATA-Kerberos-background.jpg)

1.  The user provides the Domain Name, user, and password to access their computer.

2.  The computer authenticates the user by sending a request to the Key Distribution Center (KDC) residing on the Domain Controller (DC).

3.  Accordingly, the KDC provides the computer with a Ticket Granting Ticket (TGT) for the user. The TGT is an identifier which enables the user to request access to services without having to re-supply the credentials.

4.  Each time the user attempts to access a service, it first identifies itself to the Domain Controller, with the TGT as provided earlier by the KDC. The DC provides the user with a Ticket Granting Service (TGS) for the particular requested service.

5.  The user provides the service ticket to the service. Since the ticket was validated by the DC the service grants access according to the authorization data provided in the TGS.

Accordingly, the connection between the user and the service is established.

For more information regarding Pass-the-Ticket attacks, please read Mitigating Pass-the-Hash (PtH) attacks and other Credential Theft prepared by Microsoft Trustworthy Computing [here](http://www.microsoft.com/en-us/download/confirmation.aspx?id=36036)

## What is Brute Force?
Brute Force is an attack where attackers attempt to guess a user’s password by authenticating with multiple passwords in a short period of time. The simplest form of Brute Force is directed against a single account: the attacker tries all possible passwords on one user ID until one succeeds.

To protect against Brute Force attacks users who authenticate with passwords should set strong passwords or passphrases that include characters from multiple sets that are as long as your users can easily remember.

## What is Reconnaissance?
Reconnaissance is the scanning of networks to discover valid information that can be used to map out the environment to assist the hacker in their attack.  Some types of information that an attacker might be interested in are: IP addresses being used, domain name system (DNS) names, user account names, and computer account names. Reconnaissance does no harm itself. Reconnaissance is somewhat analogous to a thief staking out a home before the actual burglary. 
Investigating a reconnaissance event can assist in stopping a more harmful attack from taking place.

## What is broken trust?
When a computer account’s password does not match the password in the domain for the computer account the computer is not able to create a secure channel with the domain, this is also known as “broken trust”. When trust is broken, the computer can no longer be managed by Active Directory including applying and enforcing security policies.

## What is lateral movement?
Lateral movement is a Pass-the-Hash attack activity. In this activity, the attacker uses the credentials obtained from a compromised computer to gain access to another computer of the same value to the organization. For example, the attacker could use stolen credentials for the built-in local administrator account from the compromised computer to gain access to another computer that has the same username and password.

## What is the deployment process?
After identifying the domain controllers you want to monitor you need to perform the following steps.

1.  Configure port mirroring, the domain controllers should be the source and the ATA Gateway should be configured as the destination.

2.  Install the ATA Center

3.  Configure the ATA Domain Connectivity settings

4.  Install the ATA Gateway

5.  Configure the ATA Gateway settings

6.  Configure Alert settings (optional)

## In which geographies is ATA  generally available?
The product is available worldwide except China.

## In which languages is ATA available?
Microsoft Advanced Threat Analytics supports the following languages:
English, German, Spanish, French, and Japanese.

## How is ATA licensed?
ATA is licensed either standalone with a Client Management License (CML) – available per User or per Operating System Environment (OSE) – or through one of three Microsoft license suites that provide multiple Microsoft products or cloud services at a significant discount over standalone license prices:

-   Enterprise Client Access License (ECAL) Suite

-   Enterprise Mobility Suite (EMS)

-   Enterprise Cloud Suite (ECS)

If the customer covers only some of their users with one of the three license suites above, but have additional users who will get monitored by ATA (since ATA monitors domain controllers that manage traffic for multiple users), then customers can either true up on the suites to cover those additional users, or, if those users don’t need all the suite products, then the customer can just buy the ATA standalone SKU to cover those remaining users.  For more information about Microsoft Advanced Threat Analytics pricing  visit the ATA purchasing page.

## What’s the path for technical questions for Microsoft Advanced Threat Analytics? How do you troubleshoot and get additional support if needed?
Technical support for Advanced Threat Analytics is available through [discussion forums](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata).

## See Also
[ATA Release Notes](../Topic/ATA-Release-Notes.md)
 [ATA Architecture](../Topic/ATA-Architecture.md)
 [ATA Deployment Guide](../Topic/ATA-Deployment-Guide.md)

