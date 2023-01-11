---
title: Microsoft Defender for Identity exfiltration alerts 
description: This article explains the Microsoft Defender for Identity alerts issued when attacks typically part of exfiltration phase efforts are detected against your organization.
ms.date: 12/06/2022
ms.topic: conceptual
---

# Exfiltration alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](reconnaissance-alerts.md)
1. [Compromised credentials](compromised-credentials-alerts.md)
1. [Lateral Movements](lateral-movement-alerts.md)
1. [Domain dominance](domain-dominance-alerts.md)
1. **Exfiltration**

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Exfiltration** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network. In this article, you'll learn to understand, classify, prevent, and remediate the following attacks:

> [!div class="checklist"]
>
> - Data exfiltration over SMB (external ID 2030)
> - Suspicious communication over DNS (external ID 2031)

## Data exfiltration over SMB (external ID 2030)

**Description**

Domain controllers hold the most sensitive organizational data. For most attackers, one of their top priorities is to gain domain controller access, to steal your most sensitive data. For example, exfiltration of the Ntds.dit file, stored on the DC, allows an attacker to forge Kerberos ticket granting tickets(TGT) providing authorization to any resource. Forged Kerberos TGTs enable the attacker to set the ticket expiration to any arbitrary time. A [!INCLUDE [Product short](includes/product-short.md)] **Data exfiltration over SMB** alert is triggered when suspicious transfers of data are observed from your monitored domain controllers.

**MITRE**

|Primary MITRE tactic  |[Exfiltration (TA0010)](https://attack.mitre.org/tactics/TA0010)  |
|---------|---------|
|Secondary MITRE tactic    | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008),[Command and Control (TA0011)](https://attack.mitre.org/tactics/TA0011)        |
|MITRE attack technique  | [Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/), [Lateral Tool Transfer (T1570) ](https://attack.mitre.org/techniques/T1570/)      |
|MITRE attack sub-technique | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (T1048.003)](https://attack.mitre.org/techniques/T1048/003/)        |

**TP, B-TP, or FP**

1. Are these users supposed to copy these files, to this computer?
    - If the answer to the previous question is **yes**, **Close** the security alert, and exclude the computer as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source users](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).
1. Investigate the [source and destination computers](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices) of the copies.

**Suggested remediation and steps for prevention**

1. Reset the password of the source users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Find the files that were copied and remove them.  
    Check if there were other activities on these files. Where they transferred to another place? Check if they were transferred outside the organization network?
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. If one of the files is the **ntds.dit** file:
    - Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in the [KRBTGT account article](/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account).
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and won't work again until they are renewed or in some cases, the service is restarted.

    - **Plan carefully before performing the KRBTGT double reset. The KRBTGT double reset impacts all computers, servers, and users in the environment.**

    - Close all existing sessions tot the domain controllers.

## Suspicious communication over DNS (external ID 2031)

*Previous name*: Suspicious communication over DNS

**Description**

The DNS protocol in most organizations is typically not monitored and rarely blocked for malicious activity. Enabling an attacker on a compromised machine, to abuse the DNS protocol. Malicious communication over DNS can be used for data exfiltration, command, and control, and/or evading corporate network restrictions.

**MITRE**

|Primary MITRE tactic  | [Exfiltration (TA0010)](https://attack.mitre.org/tactics/TA0010)  |
|---------|---------|
|MITRE attack technique  | [Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/), [Exfiltration Over C2 Channel (T1041)](https://attack.mitre.org/techniques/T1041/), [Scheduled Transfer (T1029)](https://attack.mitre.org/techniques/T1029/), [Automated Exfiltration (T1020)](https://attack.mitre.org/techniques/T1020/), [Application Layer Protocol (T1071)](https://attack.mitre.org/techniques/T1071/)       |
|MITRE attack sub-technique | [DNS (T1071.004)](https://attack.mitre.org/techniques/T1071/004/), [Exfiltration over Unencrypted/Obfuscated Non-C2 Protocol (T1048.003)](https://attack.mitre.org/techniques/T1048/003/)       |

**TP, B-TP, or FP?**

Some companies legitimately use DNS for regular communication. To determine the status of the security alert:

1. Check if the registered query domain belongs to a trusted source, such as your antivirus provider.
    - Consider it a **B-TP** activity if the domain is known and trusted, and DNS queries are permitted. *Close* the security alert, and exclude the domain from future alerts.
    - If the registered query domain is not trusted, identify the process creating the request on the source computer. Use [Process Monitor](/sysinternals/downloads/procmon) to assist with this task.

**Understand the scope of the breach**

1. On the destination computer, which should be a DNS server, check for the records of the domain in question.
    - What IP is it correlated to?
    - Who is the owner of the domain?
    - Where is the IP?
1. Investigate the [source and destination computers](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).

**Suggested remediation and steps for prevention**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. If after your investigation, the registered query domain remains not trusted, we recommend blocking the destination domain to avoid all future communication.

> [!NOTE]
> *Suspicious communication over DNS* security alerts list the suspected domain. New domains, or domains recently added that are not yet known or recognized by [!INCLUDE [Product short](includes/product-short.md)] but are known to or part of your organization can be closed.

## See Also

- [Investigate a computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices)
- [Working with security alerts](/defender-for-identity/manage-security-alerts)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
