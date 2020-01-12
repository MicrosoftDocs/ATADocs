---
# required metadata

title: What is Azure Advanced Threat Protection (Azure ATP)? | Microsoft Docs
description: Explains what Azure Advanced Threat Protection (Azure ATP) is and what kinds of suspicious activities it can detect
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 05/07/2019
ms.topic: article
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 2d14d0e9-1b03-4bcc-ae97-8fd41526ffc5

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# What is Azure Advanced Threat Protection?
Azure Advanced Threat Protection (ATP) is a cloud-based security solution that leverages your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization. 
Azure ATP enables SecOp analysts and security professionals struggling to detect advanced attacks in hybrid environments to:  
- Monitor users, entity behavior, and activities with learning-based analytics  
- Protect user identities and credentials stored in Active Directory  
- Identify and investigate suspicious user activities and advanced attacks throughout the kill chain 
- Provide clear incident information on a simple timeline for fast triage 
 
## Monitor and profile user behavior and activities  
Azure ATP monitors and analyzes user activities and information across your network, such as permissions and group membership, creating a behavioral baseline for each user. Azure ATP then identifies anomalies with adaptive built-in intelligence, giving you insights into suspicious activities and events, revealing the advanced threats, compromised users, and insider threats facing your organization. Azure ATP’s proprietary sensors monitor organizational domain controllers, providing a comprehensive view for all user activities from every device. 
 
## Protect user identities and reduce the attack surface   
Azure ATP provides you invaluable insights on identity configurations and suggested security best-practices. Through security reports and user profile analytics, Azure ATP helps dramatically reduce your organizational attack surface, making it harder to compromise user credentials, and advance an attack. Azure ATP’s visual Lateral Movement Paths help you quickly understand exactly how an attacker can move laterally inside your organization to compromise sensitive accounts and assists in preventing those risks in advance. Azure ATP security reports help you identify users and devices that authenticate using clear-text passwords and provide additional insights to improve your organizational security posture and policies.  
 
## Identify suspicious activities and advanced attacks across the cyber-attack kill-chain 

Typically, attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets – such as sensitive accounts, domain administrators, and highly sensitive data. Azure ATP identifies these advanced threats at the source throughout the entire cyber-attack kill chain: 

### Reconnaissance 
Identify rogue users and attackers’ attempts to gain information. Attackers are searching for information about user names, users’ group membership, IP addresses assigned to devices, resources, and more, using a variety of methods.  

### Compromised credentials
Identify attempts to compromise user credentials using brute force attacks, failed authentications, user group membership changes, and other methods.  

### Lateral movements
Detect attempts to move laterally inside the network to gain further control of sensitive users, utilizing methods such as Pass the Ticket, Pass the Hash, Overpass the Hash and more.  

### Domain dominance
Highlighting attacker behavior if domain dominance is achieved, through remote code execution on the domain controller, and methods such as DC Shadow, malicious domain controller replication, Golden Ticket activities, and more.

## Investigate alerts and user activities  
Azure ATP is designed to reduce general alert noise, providing only relevant, important security alerts in a simple, real-time organizational attack timeline. The Azure ATP attack timeline view allows you to easily stay focused on what matters, leveraging the intelligence of smart analytics. Use Azure ATP to quickly investigate threats, and gain insights across the organization for users, devices, and network resources. Seamless integration with Windows Defender ATP provides another layer of enhanced security by additional detection and protection against advanced persistent threats on the operating system.  

## Additional resources for Azure ATP  
### Start a free trial  
[https://signup.microsoft.com/Signup?OfferId=87dd2714-d452-48a0-a809-d2f58c4f68b7&ali=1](https://signup.microsoft.com/Signup?OfferId=87dd2714-d452-48a0-a809-d2f58c4f68b7&ali=1 "Enterprise Mobility + Security E5")
 
### Follow Azure ATP on Microsoft Tech Community  
[https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection "Azure ATP on Microsoft Tech Community")
 
### Join the Azure ATP Yammer community 
[https://www.yammer.com/azureadvisors/#/threads/inGroup?type=in_group&feedId=9386893](https://www.yammer.com/azureadvisors/#/threads/inGroup?type=in_group&feedId=9386893 "Azure ATP Yammer community")
 
### Visit the Azure ATP product page  
[https://azure.microsoft.com/features/azure-advanced-threat-protection/](https://azure.microsoft.com/features/azure-advanced-threat-protection/ "Azure ATP product page")

### Learn more about Azure ATP architecture
 [Azure ATP Architecture](atp-architecture.md)
 
## Microsoft Ignite
Microsoft Ignite 2018 featured multiple sessions focused on [Azure Advanced Threat Protection](https://myignite.techcommunity.microsoft.com/sessions?q=Azure%2520Advanced%2520Threat%2520Protection&t=%257B%2522from%2522%253A%25222018-09-23T08%253A00%253A00-04%253A00%2522%252C%2522to%2522%253A%25222018-09-28T19%253A00%253A00-04%253A00%2522%257D). Sessions were recorded, so if you missed the event, we recommend you watch here:

### Azure ATP 
[BRK3117](https://myignite.techcommunity.microsoft.com/sessions/65780?source=sessions#ignite-html-anchor) - SecOp and incident response with Azure ATP - watch the [YouTube video](https://www.youtube.com/watch?v=QXZIfH0wP3Q)

### Azure ATP and Azure AD IP (Active Directory Identity Protection)
[BRK3237](https://myignite.techcommunity.microsoft.com/sessions/64523?source=sessions#ignite-html-anchor) - Securing your hybrid cloud environment with Azure AD Identity Protection and Azure ATP  - watch the [YouTube video](https://www.youtube.com/watch?v=X7CXaok6GbM)

[BRK2157](https://myignite.techcommunity.microsoft.com/sessions/65776?source=sessions#ignite-html-anchor) - Accelerate deployment and adoption of Microsoft Information Protection solutions - watch the [YouTube video](https://www.youtube.com/watch?v=Foh-XDVbPog)

For a summary of Azure ATP announcements that were made at Ignite 2018, see the blog post -	[Azure Advanced Threat Protection Expands Integrations, Detections, and Forensic Capabilities](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Azure-Advanced-Threat-Protection-Expands-Integrations-Detections/ba-p/262409).

## What's next? 

We recommend deploying Azure ATP in three phases:  

### Phase 1

1. Set up Azure ATP to protect your primary environments. Azure ATP's fast deployment model enables you to start protecting your organization today. [Install Azure ATP](install-atp-step1.md)  
2. Set [sensitive accounts](sensitive-accounts.md) and [honeytoken accounts](install-atp-step7.md).
3. Review reports and [lateral movement paths](use-case-lateral-movement-path.md).  


### Phase 2

1. Protect all the domain controllers and [forests](atp-multi-forest.md) in your organization.  
2. Monitor all [alerts](working-with-suspicious-activities.md) – investigate lateral movement & domain dominance alerts.  
3. Work with the [Security Alert guide](suspicious-activity-guide.md) to understand threats and triage potential attacks.


### Phase 3

1. Integrate Azure ATP alerts into your SecOp workflows.

## See Also
- [Azure ATP frequently asked questions](atp-technical-faq.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
