---
# required metadata

title: Azure ATP exfiltration alerts tutorial
d|Description: This article explains the Azure ATP alerts issued when attacks typically part of exfiltration phase efforts are detected against your organization.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 03/01/2020
ms.topic: tutorial
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
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

# Tutorial: Exfiltration alerts

Typically, cyber attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. Azure ATP identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](atp-reconnaissance-alerts.md)
2. [Compromised credentials](atp-compromised-credentials-alerts.md)
3. [Lateral Movements](atp-lateral-movement-alerts.md)
4. [Domain dominance](atp-domain-dominance-alerts.md)
5. **Exfiltration**

To learn more about how to understand the structure, and common components of all Azure ATP security alerts, see [Understanding security alerts](understanding-security-alerts.md)

The following security alerts help you identify and remediate **Exfiltration** phase suspicious activities detected by Azure ATP in your network. In this tutorial, learn to understand, classify, prevent, and remediate the following attacks:

> [!div class="checklist"]
>
> * Suspicious communication over DNS (external ID 2031)
> * Data exfiltration over SMB (external ID 2030)

## Suspicious communication over DNS (external ID 2031)

*Previous name*: Suspicious communication over DNS

**Description**

The DNS protocol in most organizations is typically not monitored and rarely blocked for malicious activity. Enabling an attacker on a compromised machine, to abuse the DNS protocol. Malicious communication over DNS can be used for data exfiltration, command, and control, and/or evading corporate network restrictions.

**TP, B-TP, or FP?**

Some companies legitimately use DNS for regular communication. To determine the status of the security alert:

1. Check if the registered query domain belongs to a trusted source, such as your antivirus provider.
    - Consider it a **B-TP** activity if the domain is known and trusted, and DNS queries are permitted. *Close* the security alert, and exclude the domain from future alerts.
    - If the registered query domain is not trusted, identify the process creating the request on the source computer. Use [Process Monitor](https://docs.microsoft.com/sysinternals/downloads/procmon) to assist with this task.

**Understand the scope of the breach**

1. On the destination computer, which should be a DNS server, check for the records of the domain in question.
    - What IP is it correlated to?
    - Who is the owner of the domain?
    - Where is the IP?
1. Investigate the [source and destination computers](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
2. If after your investigation, the registered query domain remains not trusted, we recommend blocking the destination domain to avoid all future communication.

> [!NOTE]
> *Suspicious communication over DNS* security alerts list the suspected domain. New domains, or domains recently added that are not yet known or recognized by Azure ATP but are known to or part of your organization can be closed.

## Data exfiltration over SMB (external ID 2030)

**Description**

Domain controllers hold the most sensitive organizational data. For most attackers, one of their top priorities is to gain domain controller access, to steal your most sensitive data. For example, exfiltration of the Ntds.dit file, stored on the DC, allows an attacker to forge Kerberos ticket granting tickets(TGT) providing authorization to any resource. Forged Kerberos TGTs enable the attacker to set the ticket expiration to any arbitrary time. An Azure ATP **Data exfiltration over SMB** alert is triggered when suspicious transfers of data are observed from your monitored domain controllers.

**TP, B-TP, or FP**

1. Are these users supposed to copy these files, to this computer?
    - If the answer to the previous question is **yes**, **Close** the security alert, and exclude the computer as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source users](investigate-a-user.md).
2. Investigate the [source and destination computers](investigate-a-computer.md) of the copies.

**Suggested remediation and steps for prevention**

1. Reset the password of the source users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
2. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Find the files that were copied and remove them.  
    Check if there were other activities on these files. Where they transferred to another place? Check if they were transferred outside the organization network?
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can use the [**Confirm user compromised**](/cloud-app-security/accounts#governance-actions) action in the Cloud App Security portal.
3. If one of the files is the **ntds.dit** file:
    - Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51).
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and won't work again until they are renewed or in some cases, the service is restarted.

    - **Plan carefully before performing the KRBTGT double reset. The KRBTGT double reset impacts all computers, servers, and users in the environment.**

    - Close all existing sessions tot the domain controllers.

## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](atp-reconnaissance-alerts.md)
- [Compromised credential alerts](atp-compromised-credentials-alerts.md)
- [Lateral movement alerts](atp-lateral-movement-alerts.md)
- [Domain dominance alerts](atp-domain-dominance-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
