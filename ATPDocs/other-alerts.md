---
title: Microsoft Defender for Identity other security alerts
description: This article explains Microsoft Defender for Identity alerts issued when other attacks are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Other alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Persistence alerts](persistence-privilege-escalation-alerts.md)
1. [Credential access alerts](credential-access-alerts.md)
1. [Discovery alerts](reconnaissance-discovery-alerts.md)
1. [Lateral movement alerts](lateral-movement-alerts.md)
1. **Other**

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Other** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network.

## Suspected DCShadow attack (domain controller promotion) (external ID 2028)

*Previous name:* Suspicious domain controller promotion (potential DCShadow attack)

**Description**

A domain controller shadow (DCShadow) attack is an attack designed to change directory objects using malicious replication. This attack can be performed from any machine by creating a rogue domain controller using a replication process.

In a DCShadow attack, RPC, and LDAP are used to:

1. Register the machine account as a domain controller (using domain admin rights).
1. Perform replication (using the granted replication rights) over DRSUAPI and send changes to directory objects.

In this [!INCLUDE [Product short](includes/product-short.md)] detection, a security alert is triggered when a machine in the network tries to register as a rogue domain controller.

**MITRE**

|Primary MITRE tactic  | [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005)  |
|---------|---------|
|MITRE attack technique  | [Rogue Domain Controller (T1207)](https://attack.mitre.org/techniques/T1207/)        |
|MITRE attack sub-technique |   N/A      |

**Learning period**

None

**TP, B-TP, or FP**

If the source computer is a domain controller, failed or low certainty resolution can prevent [!INCLUDE [Product short](includes/product-short.md)] from being able to confirm identification.

1. Check if the source computer is a domain controller?
    If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Changes in your Active Directory can take time to synchronize.

1. Is the source computer a newly promoted domain controller? If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Servers and applications might replicate data from Active Directory, such as Azure AD Connect or network performance monitoring devices.

1. Check if this source computer is supposed to generate this type of activity?

    - If the answer is **yes**, but the source computer should not continue generating this type of activity in the future, fix the configuration of the server/application. **Close** the security alert as a  **B-TP** activity.

    - If the answer is **yes** and the source computer should continue generating this type of activity in the future, **Close** the security alert as a **B-TP** activity, and exclude the computer to avoid additional benign alerts.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. Look at the Event Viewer to see [Active Directory events that it records in the directory services log](/previous-versions/windows/it-pro/windows-2000-server/cc961809(v=technet.10)/). You can use the log to monitor changes in Active Directory. By default, Active Directory only records critical error events, but if this alert recurs, enable this audit on the relevant domain controller for further investigation.

**Suggested remediation and steps for prevention:**

**Remediation:**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised.
    Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
1. Replicate directory changes all.
1. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](/SharePoint/administration/user-profile-service-administration). You can use [AD ACL Scanner](/archive/blogs/pfesweplat/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool) or create a Windows PowerShell script to determine who has these permissions in the domain.

> [!NOTE]
> Suspicious domain controller promotion (potential DCShadow attack) alerts are supported by [!INCLUDE [Product short](includes/product-short.md)] sensors only.

## Suspected DCShadow attack (domain controller replication request) (external ID 2029)

*Previous name:* Suspicious replication request (potential DCShadow attack)

**Description**

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with other domain controllers. Given necessary permissions, attackers can grant rights for their machine account, allowing them to impersonate a domain controller. Attackers strive to initiate a malicious replication request, allowing them to change Active Directory objects on a genuine domain controller, which can give the attackers persistence in the domain.
In this detection, an alert is triggered when a suspicious replication request is generated against a genuine domain controller protected by [!INCLUDE [Product short](includes/product-short.md)]. The behavior is indicative of techniques used in domain controller shadow attacks.

**MITRE**

|Primary MITRE tactic  | [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005)  |
|---------|---------|
|MITRE attack technique  | [Rogue Domain Controller (T1207)](https://attack.mitre.org/techniques/T1207/)        |
|MITRE attack sub-technique |   N/A      |

**Learning period**

None

**TP, B-TP, or FP**

If the source computer is a domain controller, failed or low certainty resolution can prevent [!INCLUDE [Product short](includes/product-short.md)] from identification.

1. Check if the source computer is a domain controller?
    If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Changes in your Active Directory can take time to synchronize.

1. Is the source computer a newly promoted domain controller? If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Servers and applications might replicate data from Active Directory, such as Azure AD Connect or network performance monitoring devices.

1. Was this source computer supposed to generate this type of activity?

    - If the answer is **yes**, but the source computer should not continue generating this type of activity in the future, fix the configuration of the server/application. **Close** the security alert as a  **B-TP** activity.

    - If the answer is **yes**, and the source computer should continue generating this type of activity in the future, **Close** the security alert as a **B-TP** activity, and exclude the computer to avoid additional **B-TP** alerts.

**Understand the scope of the breach**

1. Investigate the source [computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).

**Suggested remediation and steps for prevention**

**Remediation:**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised.
    Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Remediate the data that was replicated on the domain controllers.

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
1. Replicate directory changes all.
1. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](/SharePoint/administration/user-profile-service-administration). You can use [AD ACL Scanner](/archive/blogs/pfesweplat/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool) or create a Windows PowerShell script to determine who in the domain has these permissions.

> [!NOTE]
> Suspicious replication request (potential DCShadow attack) alerts are supported by [!INCLUDE [Product short](includes/product-short.md)] sensors only.

## Suspicious VPN connection (external ID 2025)

*Previous name:* Suspicious VPN connection

**Description**

[!INCLUDE [Product short](includes/product-short.md)] learns the entity behavior for users VPN connections over a sliding period of one month.

The VPN-behavior model is based on the machines users log in to and the locations the users connect from.

An alert is opened when there is a deviation from the user's behavior based on a machine learning algorithm.

**MITRE**

|Primary MITRE tactic  | [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005)  |
|---------|---------|
|Secondary MITRE tactic    | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003)        |
|MITRE attack technique  | [External Remote Services (T1133)](https://attack.mitre.org/techniques/T1133/)        |
|MITRE attack sub-technique |     N/A    |

**Learning period**

30 days from the first VPN connection, and at least 5 VPN connections in the last 30 days, per user.

**TP, B-TP, or FP**

1. Is the suspicious user supposed to be performing these operations?
    1. Did the user recently change their location?
    1. Is the user travelling and connecting from a new device?

If the answer is yes to the questions above, **Close** the security alert as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. If there is a source user, [investigate the user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).

**Suggested remediation and steps for prevention**

1. Reset the password of the user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Consider blocking this user from connecting using VPN.
1. Consider blocking this computer from connecting using VPN.
1. Check if there are other users connected through VPN from these locations, and check if they are compromised.


## Remote code execution attempt (external ID 2019)

*Previous name:* Remote code execution attempt

**Description**

Attackers who compromise administrative credentials or use a zero-day exploit can execute remote commands on your domain controller or AD FS server. This can be used for gaining persistency, collecting information, denial of service (DOS) attacks or any other reason. [!INCLUDE [Product short](includes/product-short.md)] detects PSexec, Remote WMI, and PowerShell connections.

**MITRE**

|Primary MITRE tactic  | [Execution (TA0002)](https://attack.mitre.org/tactics/TA0002)  |
|---------|---------|
|Secondary MITRE tactic    |  [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)       |
|MITRE attack technique  | [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/),[Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)         |
|MITRE attack sub-technique |  [PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/), [Windows Remote Management (T1021.006)](https://attack.mitre.org/techniques/T1021/006/)      |

**Learning period**

None

**TP, B-TP, or FP**

Administrative workstations, IT team members, and service accounts can all perform legitimate administrative tasks against domain controllers.

1. Check if the source computer or user is supposed to run those types of commands on your domain controller?
    - If the source computer or user is supposed to run those types of commands, **Close** the security alert as a **B-TP** activity.
    - If the source computer or user is supposed to run those commands on your domain controller, and will continue to do so, it is a **B-TP** activity. **Close** the security alert and exclude the computer.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices) and [user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).
1. Investigate the [domain controller](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices
).

**Suggested remediation and steps for prevention:**

**Remediation**

1. Reset the password of the source users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the domain controllers by:
    - Remediate the remote code execution attempt.
    - Look for users logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

**Prevention**

1. Restrict remote access to domain controllers from non-Tier 0 machines.
1. Implement [privileged access](/windows-server/identity/securing-privileged-access/securing-privileged-access). allowing only hardened machines to connect to domain controllers for admins.
1. Implement less-privileged access on domain machines to allow specific users the right to create services.

> [!NOTE]
> Remote code execution attempt alerts on attempted use of Powershell commands are only supported by [!INCLUDE [Product short](includes/product-short.md)] sensors.

## Suspicious service creation (external ID 2026)

*Previous name:* Suspicious service creation

**Description**

A suspicious service has been created on a domain controller or AD FS server in your organization. This alert relies on event 7045 to identify this suspicious activity.

**MITRE**

|Primary MITRE tactic  | [Execution (TA0002)](https://attack.mitre.org/tactics/TA0002) |
|---------|---------|
|Secondary MITRE tactic    |   [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004), [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005), [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)      |
|MITRE attack technique  | [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/), [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/), [System Services (T1569)](https://attack.mitre.org/techniques/T1569/), [Create or Modify System Process (T1543)](https://attack.mitre.org/techniques/T1543/)      |
|MITRE attack sub-technique |   [Service Execution (T1569.002)](https://attack.mitre.org/techniques/T1569/002/), [Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/)      |

**Learning period**

None

**TP, B-TP, or FP**

Some administrative tasks are legitimately performed against domain controllers by administrative workstations, IT team members, and service accounts.

1. Is the source user/computer supposed to run these types of services on the domain controller?
    - If the source user or computer is supposed to run these types of services, and should not continue to, **Close** the alert as a **B-TP** activity.
    - If the source user or computer  is supposed to run these types of services, and should continue to, **Close** the security alert as a **B-TP** activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [source user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).
1. Investigate the [destination computers](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices) the services were created on.

**Suggested remediation and steps for prevention**

**Remediation**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the domain controllers.
    - Remediate the suspicious service.
    - Look for users logged on around the time of the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Locate the computer the source user was active on.
    - Check the computers the user was logged into around the same time as the activity, and check if these computers are also compromised.

**Prevention:**

1. Restrict remote access to domain controllers from non-Tier 0 machines.
1. Implement [privileged access](/windows-server/identity/securing-privileged-access/securing-privileged-access) to allow only hardened machines to connect to domain controllers for administrators.
1. Implement less-privileged access on domain machines to give only specific users the right to create services.

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

## See also

- [Investigate a computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices)
- [Investigate a user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users)
- [Working with security alerts](/defender-for-identity/manage-security-alerts)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [[!INCLUDE [Product short](includes/product-short.md)] SIEM log reference](cef-format-sa.md)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
