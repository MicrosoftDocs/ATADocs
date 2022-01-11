---
title: Microsoft Defender for Identity domain dominance security alerts
description: This article explains the Microsoft Defender for Identity alerts issued when attacks typically part of domain dominance phase efforts are detected against your organization.
ms.date: 12/23/2020
ms.topic: tutorial
---

# Tutorial: Domain dominance alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](reconnaissance-alerts.md)
1. [Compromised credentials](compromised-credentials-alerts.md)
1. [Lateral Movements](lateral-movement-alerts.md)
1. **Domain dominance**
1. [Exfiltration](exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Domain dominance** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network. In this tutorial, learn how to understand, classify, prevent, and remediate the following attacks:

> [!div class="checklist"]
>
> - Malicious request of Data Protection API master key (external ID 2020)
> - Remote code execution attempt (external ID 2019)
> - Suspected DCShadow attack (domain controller promotion) (external ID 2028)
> - Suspected DCShadow attack (domain controller replication request) (external ID 2029)
> - Suspected DCSync attack (replication of directory services) (external ID 2006)
> - Suspected Golden Ticket usage (encryption downgrade) (external ID 2009)
> - Suspected Golden Ticket usage (forged authorization data) (external ID 2013)
> - Suspected Golden Ticket usage (nonexistent account) (external ID 2027)
> - Suspected Golden Ticket usage (ticket anomaly) (external ID 2032)
> - Suspected Golden Ticket usage (ticket anomaly using RBCD) (external ID 2040)
> - Suspected Golden Ticket usage (time anomaly) (external ID 2022)
> - Suspected Skeleton Key attack (encryption downgrade) (external ID 2010)
> - Suspicious additions to sensitive groups (external ID 2024)
> - Suspicious service creation (external ID 2026)

## Malicious request of Data Protection API master key (external ID 2020)

*Previous name:* Malicious Data Protection Private Information Request

**Description**

The Data Protection API (DPAPI) is used by Windows to securely protect passwords saved by browsers, encrypted files, and other sensitive data. Domain controllers hold a backup master key that can be used to decrypt all secrets encrypted with DPAPI on domain-joined Windows machines. Attackers can use the master key to decrypt any secrets protected by DPAPI on all domain-joined machines.
In this detection, a [!INCLUDE [Product short](includes/product-short.md)] alert is triggered when the DPAPI is used to retrieve the backup master key.

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)  |
|---------|---------|
|MITRE attack technique  | [Credentials from Password Stores (T1555)](https://attack.mitre.org/techniques/T1555/)        |
|MITRE attack sub-technique |  N/A     |

**Learning period**

None

**TP, B-TP, or FP?**

Advanced security scanners may legitimately generate this type of activity against Active Directory.

1. Check if the source computer is running an organization-approved advanced security scanner against Active Directory?

    - If the answer is **yes**, and it should not be running, fix the application configuration. This alert is a **B-TP** and can be **Closed**.
    - If the answer is **yes**, and it should always do this, **Close** the alert, and exclude that computer, it is probably a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
1. If a [source user](investigate-a-user.md) exists, investigate.

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. The stolen private key is never changed. Meaning the actor can always use the stolen key to decrypt protected data in the target domain. A methodological way to change this private key does not exist.
    - To create a key, use the current private key, create a key, and re-encrypt every domain master key with the new private key.

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

1. Investigate the [source computer](investigate-a-computer.md) and [user](investigate-a-user.md).
1. Investigate the [domain controller](investigate-a-computer.md).

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

1. Investigate the [source computer](investigate-a-computer.md).
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

1. Investigate the source [computer](investigate-a-computer.md).

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

## Suspected DCSync attack (replication of directory services) (external ID 2006)

*Previous name:* Malicious replication of directory services

**Description**

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with all other domain controllers. Given necessary permissions, attackers can initiate a replication request, allowing them to retrieve the data stored in Active Directory, including password hashes.

In this detection, an alert is triggered when a replication request is initiated from a computer that is not a domain controller.

> [!NOTE]
> If you have domain controllers on which [!INCLUDE [Product short](includes/product-short.md)] sensors are not installed, those domain controllers are not covered by [!INCLUDE [Product short](includes/product-short.md)]. When deploying a new domain controller on an unregistered or unprotected domain controller, it may not immediately be identified by [!INCLUDE [Product short](includes/product-short.md)] as a domain controller. It is highly recommended to install the [!INCLUDE [Product short](includes/product-short.md)] sensor on every domain controller to get full coverage.

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)  |
|---------|---------|
|Secondary MITRE tactic    | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003)      |
|MITRE attack technique  | [OS Credential Dumping (T1003)](https://attack.mitre.org/techniques/T1003/)        |
|MITRE attack sub-technique | [DCSync (T1003.006)](https://attack.mitre.org/techniques/T1003/006/)        |

**Learning period**

None

**TP, B-TP, or FP**

If the source computer is a domain controller, failed or low certainty resolution can prevent [!INCLUDE [Product short](includes/product-short.md)] from identification.

1. Check if the source computer is a domain controller?
    If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Changes in your Active Directory can take time to synchronize.

1. Is the source computer a newly promoted domain controller? If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Servers and applications might replicate data from Active Directory, such as Azure AD Connect or network performance monitoring devices.

1. Was this source computer was supposed to generate this type of activity?

    - If the answer is **yes**, but the source computer should not continue to generate this type of activity in the future, fix the configuration of the server/application. **Close** the security alert as a  **B-TP** activity.

    - If the answer is **yes**, and the source computer should continue to generate this type of activity in the future, **Close** the security alert as a **B-TP** activity, and exclude the computer to avoid additional benign alerts.

**Understand the scope of the breach**

1. Investigate the source [computer](investigate-a-computer.md) and [user](investigate-a-user.md).

**Suggested remediation and steps for prevention:**

**Remediation:**

1. Reset the password of the source users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
1. Replicate directory changes all.
1. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](/SharePoint/administration/user-profile-service-administration). You can use [AD ACL Scanner](/archive/blogs/pfesweplat/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool) or create a Windows PowerShell script to determine who in the domain has these permissions.

## Suspected Golden Ticket usage (encryption downgrade) (external ID 2009)

*Previous name:* Encryption downgrade activity

**Description**

Encryption downgrade is a method of weakening Kerberos by downgrading the encryption level of different protocol fields that normally have the highest level of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, [!INCLUDE [Product short](includes/product-short.md)] learns the Kerberos encryption types used by computers and users, and alerts you when a weaker cypher is used that is unusual for the source computer and/or user and matches known attack techniques.

In a Golden Ticket alert, the encryption method of the TGT field of TGS_REQ (service request) message from the source computer was detected as downgraded compared to the previously learned behavior. This is not based on a time anomaly (as in the other Golden Ticket detection). In addition, in the case of this alert, there was no Kerberos authentication request associated with the previous service request, detected by [!INCLUDE [Product short](includes/product-short.md)].

**MITRE**

|Primary MITRE tactic  | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003) |
|---------|---------|
|Secondary MITRE tactic    | [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004), [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)        |
|MITRE attack technique  |  [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)       |
|MITRE attack sub-technique |  [Golden Ticket(T1558.001)](https://attack.mitre.org/techniques/T1558/001/)       |

**Learning period**

This alert has a learning period of 5 days from the start of domain controller monitoring.

**TP, B-TP, or FP**

Some legitimate resources don't support strong encryption ciphers and may trigger this alert.

1. Do all of the source users share something in common?
   1. For example, are all of your marketing personnel accessing a specific resource that could cause the alert to be triggered?
   1. Check the resources accessed by those tickets.
      - Check this in Active Directory by checking the attribute *msDS-SupportedEncryptionTypes*, of the resource service account.
   1. If there is only one resource being accessed, check if is a valid resource these users are supposed to access.

      If the answer to one of the previous questions is **yes**, it is likely to be a **B-TP** activity. Check if the resource can support a strong encryption cipher, implement a stronger encryption cipher where possible, and **Close** the security alert.

Applications might authenticate using a lower encryption cipher. Some are authenticating on behalf of users, such as IIS and SQL servers.

1. Check if the source users have something in common.
    - For example, do all of your sales personnel use a specific app that might trigger the alert?
    - Check if there are applications of this type on the source computer.
    - Check the computer roles.
    Are they servers that work with these types of applications?

     If the answer to one of the previous questions is **yes**, it is likely to be a **B-TP** activity. Check if the resource can support a strong encryption cipher,implement a stronger encryption cipher where possible, and **Close** the security alert.

**Understand the scope of the breach**

1. Investigate the [source computer and resources](investigate-a-computer.md) that were accessed.
1. Investigate the [users](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

**Remediation**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the time of the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
    - If you have Microsoft Defender for Endpoint installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.
1. Contain the resources that were accessed by this ticket.
1. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in the [KRBTGT account article](/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account).
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and they will not work again until they are renewed or in some cases, the service is restarted.
    - **Plan carefully before performing the KRBTGT double reset. The KRBTGT double reset impacts all computers, servers, and users in the environment.**

1. Make sure all domain controllers with operating systems up to Windows Server 2012 R2 are installed with [KB3011780](https://www.microsoft.com/download/details.aspx?id=44978) and all member servers and domain controllers up to 2012 R2 are up-to-date with [KB2496930](https://support.microsoft.com/help/2496930/ms11-013-vulnerabilities-in-kerberos-could-allow-elevation-of-privileg). For more information, see [Silver PAC](/security-updates/SecurityBulletins/2011/ms11-013) and [Forged PAC](/security-updates/SecurityBulletins/2014/ms14-068).

## Suspected Golden Ticket usage (forged authorization data) (external ID 2013)

Previous name: Privilege escalation using forged authorization data

**Description**

Known vulnerabilities in older versions of Windows Server allow attackers to manipulate the Privileged Attribute Certificate (PAC), a field in the Kerberos ticket that contains a user authorization data (in Active Directory this is group membership), granting attackers additional privileges.

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)  |
|---------|---------|
|MITRE attack technique  | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)        |
|MITRE attack sub-technique |   [Golden Ticket (T1558.001)](https://attack.mitre.org/techniques/T1558/001/)    |


**Learning period**

None

**TP, B-TP, or FP**

For computers that are patched with MS14-068 (domain controller) or MS11-013 (server) attempted attacks will not succeed, and will generate Kerberos error.

1. Check which resources were accessed in the security alert evidence list, and if the attempts were successful or failed.
1. Check if the accessed computers were patched, as described above?
    - If the computers were patched, **Close** the security alert as a **B-TP** activity.

Some Operating Systems or applications are known to modify the authorization data. For example, Linux and Unix services have their own authorization mechanism which may trigger the alert.

1. Is the source computer running an OS or application that has its own authorization mechanism?
    - If the source computer is running this type of authorization mechanism, consider upgrading the OS or fixing the application configuration. **Close** the alert as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
1. If there is a [source user](investigate-a-user.md), investigate.
1. Check which resources were accessed successfully and [investigate](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer
    - Find the tool that preformed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in the [KRBTGT account article](/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account).
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and they will not work again until they are renewed or in some cases, the service is restarted. Plan carefully before performing the KRBTGT double reset, because it impacts all computers, servers and users in the environment.
1. Make sure all domain controllers with operating systems up to Windows Server 2012 R2 are installed with [KB3011780](https://www.microsoft.com/download/details.aspx?id=44978) and all member servers and domain controllers up to 2012 R2 are up-to-date with [KB2496930](https://support.microsoft.com/help/2496930/ms11-013-vulnerabilities-in-kerberos-could-allow-elevation-of-privileg). For more information, see [Silver PAC](/security-updates/SecurityBulletins/2011/ms11-013) and [Forged PAC](/security-updates/SecurityBulletins/2014/ms14-068).

## Suspected Golden Ticket usage (nonexistent account) (external ID 2027)

Previous name: Kerberos golden ticket

**Description**

Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence. In this detection, an alert is triggered by a nonexistent account.

|Primary MITRE tactic  | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003) |
|---------|---------|
|Secondary MITRE tactic    | [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004), [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)        |
|MITRE attack technique  |  [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/), [Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068/), [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)       |
|MITRE attack sub-technique |  [Golden Ticket(T1558.001)](https://attack.mitre.org/techniques/T1558/001/)  

**Learning period**

None

**TP, B-TP, or FP**

Changes in Active Directory can take time to synchronize.

1. Is the user a known and valid domain user?
1. Has the user been recently added?
1. Was the user been recently deleted from Active Directory?

If the answer is **yes** to all of the previous questions, **Close** the alert, as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer and accessed resources](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

1. Contain the source computers
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
    - If you have Microsoft Defender for Endpoint installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.
1. Contain the resources that were accessed by this ticket.
1. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in the [KRBTGT account article](/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account).
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and they will not work again until they are renewed or in some cases, the service is restarted. Plan carefully before performing the KRBTGT double reset, because it impacts all computers, servers and users in the environment.

## Suspected Golden Ticket usage (ticket anomaly) (external ID 2032)

**Description**

Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence. Forged Golden Tickets of this type have unique characteristics this detection is specifically designed to identify.

**MITRE**

|Primary MITRE tactic  | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003) |
|---------|---------|
|Secondary MITRE tactic    | [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004), [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)        |
|MITRE attack technique  |  [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)       |
|MITRE attack sub-technique |  [Golden Ticket(T1558.001)](https://attack.mitre.org/techniques/T1558/001/)  

**Learning period**

None

**TP, B-TP, or FP**

Federation services might generate tickets that will trigger this alert.
1. Does the source computer host Federation services that generate these types of tickets?
    - If the source computer hosts services that generate these types of tickets, Close the security alert as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer and accessed resources](investigate-a-computer.md).
1. Investigate the [source user](investigate-a-user.md).

**Suggested remediation and steps for prevention**

1. Contain the source computers
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
    - If you have Microsoft Defender for Endpoint installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.
1. Contain the resources that were accessed by this ticket.
1. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidancein the [KRBTGT account article](/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account).
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services are  broken and cannot work again until renewed or in some cases, the service is restarted.

    **Plan carefully before performing a KRBTGT double reset. The reset impacts all computers, servers, and users in the environment.**

## Suspected Golden Ticket usage (ticket anomaly using RBCD) (external ID 2040)

**Description**

Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence. In this detection, the alert is triggered by a golden ticket that was created by setting Resource Based Constrained Delegation (RBCD) permissions using the KRBTGT account for account (user\computer) with SPN.

**MITRE**

|Primary MITRE tactic  | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003) |
|---------|---------|
|Secondary MITRE tactic    |  [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004)        |
|MITRE attack technique  |  [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)       |
|MITRE attack sub-technique |  [Golden Ticket(T1558.001)](https://attack.mitre.org/techniques/T1558/001/)  

**Learning period**

None

**TP, B-TP, or FP**

1. Federation services might generate tickets that will trigger this alert. Does the source computer host such services?
    - If yes, Close the security alert as a **B-TP**
1. View the source user's profile page and check what happened around the time of the activity.
    1. Is the user supposed to have access to this resource?
    1. Is the principal expected to access that service?
    1. Are all the users who were logged into the computer supposed to be logged into it?
    1. Are the privileges appropriate for the account?
1. Should the users who were logged in have access to these resources?
    - If you enabled Microsoft Defender for Endpoint integration, click on its icon to further investigate.

If the answer to any of the previous questions is yes, Close the security alert as a **FP**.

**Understand the scope of the breach**

1. Investigate the [source computer and resources](investigate-a-computer.md) that were accessed.
1. Investigate the [users](investigate-a-user.md).

**Suggested remediation and steps for prevention:**

1. Follow the instructions in the [unsecure Kerberos delegation](cas-isp-unconstrained-kerberos.md) security assessment.
1. Review the sensitive users listed in the alert and remove them from the resource.
1. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in the [KRBTGT account article](/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account). Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain so plan before doing so. Also, because creating a Golden Ticket requires domain admin rights, implement [Pass the hash](lateral-movement-alerts.md#suspected-identity-theft-pass-the-hash-external-id-2017) recommendations.

## Suspected Golden Ticket usage (time anomaly) (external ID 2022)

Previous name: Kerberos golden ticket

**Description**

Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence. This alert is triggered when a Kerberos ticket granting ticket is used for more than the allowed time permitted, as specified in the Maximum lifetime for user ticket.

**MITRE**

|Primary MITRE tactic  | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003) |
|---------|---------|
|Secondary MITRE tactic    | [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004), [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)        |
|MITRE attack technique  |  [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)       |
|MITRE attack sub-technique |  [Golden Ticket(T1558.001)](https://attack.mitre.org/techniques/T1558/001/)  

**Learning period**

None

**TP, B-TP, or FP**

1. In the last few hours, was there any change made to the **Maximum lifetime for user ticket** setting in group policy, that might affect the alert?
1. Is the [!INCLUDE [Product short](includes/product-short.md)] Standalone Sensor involved in this alert a virtual machine?
    - If the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor is involved, was it recently resumed from a saved state?
1. Is there a time synchronization problem in the network, where not all of the computers are synchronized?
    - Click the **Download details** button to view the Security Alert report Excel file, view the related network activities, and check if there is a difference between "StartTime" and "DomainControllerStartTime".

If the answer to the previous questions is **yes**, **Close** the security alert as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer and accessed resources](investigate-a-computer.md).
1. Investigate the [compromised user](investigate-a-user.md).

**Suggested remediation and steps for prevention**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
    - If you have Microsoft Defender for Endpoint installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.
1. Contain the resources accessed by this ticket.
1. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in the [KRBTGT account article](/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account).
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services are broken, and won't work again until they are renewed or in some cases, the service is restarted.

    **Plan carefully before performing a KRBTGT double reset. The reset impacts all computers, servers, and users in the environment.**

## Suspected skeleton key attack (encryption downgrade) (external ID 2010)

*Previous name:* Encryption downgrade activity

**Description**

Encryption downgrade is a method of weakening Kerberos using a downgraded encryption level for different fields of the protocol that normally have the highest level of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, [!INCLUDE [Product short](includes/product-short.md)] learns the Kerberos encryption types used by computers and users. The alert is issued when a weaker cypher is used that is unusual for the source computer, and/or user, and matches known attack techniques.

Skeleton Key is malware that runs on domain controllers and allows authentication to the domain with any account without knowing its password. This malware often uses weaker encryption algorithms to hash the user's passwords on the domain controller. In this alert, the learned behavior of previous KRB_ERR message encryption from domain controller to the account requesting a ticket, was downgraded.

**MITRE**

|Primary MITRE tactic  | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003)  |
|---------|---------|
|Secondary MITRE tactic    |  [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)       |
|MITRE attack technique  |   [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/),[Modify Authentication Process (T1556)](https://attack.mitre.org/techniques/T1556/)      |
|MITRE attack sub-technique |  [Domain Controller Authentication (T1556.001)](https://attack.mitre.org/techniques/T1556/001/)       |

**Understand the scope of the breach**

1. Investigate the [domain controller](investigate-a-computer.md).
1. Check if Skeleton Key has affected your domain controllers.
1. Investigate the [users](investigate-a-user.md) and [computers](investigate-a-computer.md) involved.

**Suggested remediation and prevention steps**

1. Reset the passwords of the compromised users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the domain controller.
    - Remove the malware. For more information, see [Skeleton Key Malware Analysis](https://www.virusbulletin.com/virusbulletin/2016/01/paper-digital-bian-lian-face-changing-skeleton-key-malware).
    - Look for users logged on around the same time as the suspicious activity occurred, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

## Suspicious additions to sensitive groups (external ID 2024)

**Description**

Attackers add users to highly privileged groups. Adding users is done to gain access to more resources, and gain persistency. This detection relies on profiling the group modification activities of users, and alerting when an abnormal addition to a sensitive group is seen. [!INCLUDE [Product short](includes/product-short.md)] profiles continuously.

For a definition of sensitive groups in [!INCLUDE [Product short](includes/product-short.md)], see [Working with the sensitive accounts](manage-sensitive-honeytoken-accounts.md).

The detection relies on events audited on domain controllers. Make sure your domain controllers are [auditing the events needed](configure-windows-event-collection.md).

**MITRE**

|Primary MITRE tactic  | [Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003) |
|---------|---------|
|Secondary MITRE tactic    | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)        |
|MITRE attack technique  |  [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/),[Domain Policy Modification (T1484)](https://attack.mitre.org/techniques/T1484/)      |
|MITRE attack sub-technique | N/A        |

**Learning period**

Four weeks per domain controller, starting from the first event.

**TP, B-TP, or FP**

Legitimate group modifications that occur rarely and the system didn't learn as "normal", may trigger an alert. These alerts would be considered  **B-TP**.

1. Is the group modification legitimate?
    - If the group modification is legitimate, **Close** the security alert as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the users added to groups.
    - Focus on their activities after they were added to the sensitive groups.
1. Investigate the source user.
    - Download the **Sensitive Group Modification** report to see what other modifications were made an who made them in the same time period.
1. Investigate the computers the source user was logged into, around the time of the activity.

**Suggested remediation and steps for prevention**

**Remediation:**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
    - Look for the computer the source user was active on.
    - Check which computers the user was logged into around the same time as the activity. Check if these computers are compromised.
    - If the users are compromised, reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

**Prevention:**

1. To help prevent future attacks, minimize the number of users authorized to modify sensitive groups.
1. Set up Privileged Access Management for Active Directory if applicable.

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

1. Investigate the [source user](investigate-a-user.md).
1. Investigate the [destination computers](investigate-a-computer.md) the services were created on.

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

> [!div class="nextstepaction"]
> [Exfiltration alert tutorial](exfiltration-alerts.md)

## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
