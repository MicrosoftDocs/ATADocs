---
# required metadata

title: Azure ATP exfiltration alerts tutorial | Microsoft Docs
d|Description: This article explains the Azure ATP alerts issued when attacks typically part of exfiltration phase efforts are detected against your organization.
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 1/6/2019
ms.topic: tutorial
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 452d951c-5f49-4a21-ae10-9fb38c3de302

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

# Exfiltration alerts  

Typically, cyber attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets – such as sensitive accounts, domain administrators, and highly sensitive data. Azure ATP identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

- [Reconnaissance](atp-reconnaissance.md)
- [Compromised credentials](atp-compromised-credentials-alerts.md)
- [Lateral Movements](atp-lateral-movement-alerts.md)
- [Domain dominance](atp-domain-dominance-alerts.md)
- **Exfiltration**

The following security alerts help you identify and remediate **Exfiltration** phase suspicious activities detected by Azure ATP in your network.

## Suspicious communication over DNS (external ID 2031) <a name="suspicious-communication-over-dns"></a>

*Previous name*: Suspicious communication over DNS

## Description

The DNS protocol in most organizations is typically not monitored and rarely blocked for malicious activity. This enables an attacker on a compromised machine to abuse the DNS protocol. Malicious communication over DNS can be used for data exfiltration, command, and control, and/or evading corporate network restrictions.

## TP, B-TP or FP?
 
Some companies legitimately use DNS for regular communication. To determine the status of the security alert:

1. Check if the registered query domain belongs to a trusted source, such as your antivirus provider.  
    - If the domain is known and trusted, and DNS queries are permitted, it is a **B-TP** activity. *Close* the security alert, and exclude the domain from future alerts.  
    - If the registered query domain is not trusted, identify the process creating the request on the source computer. Use [Process Monitor](https://docs.microsoft.com/sysinternals/downloads/procmon) to assist with this task.

## Understand the scope of the breach

1. On the destination computer, (should be a DNS server), check for the records of the domain in question.
    - What IP is it correlated to?
    - Who is the owner of the domain?
    - Where is the IP?
1. Investigate the [source and destination computers](investigate-a-computer.md).

## Suggested remediation and steps for prevention

1. Contain the source computer.
2. Find the tool that performed the attack and remove it.
3. Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA.
4. If, after your investigation, the registered query domain is not trusted, we recommend blocking the destination domain to avoid all future communication.

> [!NOTE]
> *Suspicious communication over DNS* security alerts list the suspected domain. New domains, or domains recently added that are not yet known or recognized by Azure ATP but are known to or part of your organization can be closed.


## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Compromised credential alerts](compromised-credential-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
