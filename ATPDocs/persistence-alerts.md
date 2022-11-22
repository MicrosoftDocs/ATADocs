---
title: Microsoft Defender for Identity persistence security alerts
description: This article explains Microsoft Defender for Identity alerts issued when persistence attacks are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Persistence alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. **Reconnaissance**
1. [Compromised credentials](compromised-credentials-alerts.md)
1. [Lateral Movements](lateral-movement-alerts.md)
1. [Domain dominance](domain-dominance-alerts.md)
1. [Exfiltration](exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Reconnaissance** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network.

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

1. Investigate the [source computer and resources](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices) that were accessed.
1. Investigate the [users](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).

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

1. Investigate the [source computer and accessed resources](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).

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

Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence. Forged Golden Tickets of this type have unique characteristics this detection is specifically designed to identify.

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

1. Investigate the [source computer and accessed resources](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. Investigate the [source user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).

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
    - If you enabled Microsoft Defender for Endpoint integration, select on its icon to further investigate.

If the answer to any of the previous questions is yes, Close the security alert as a **FP**.

**Understand the scope of the breach**

1. Investigate the [source computer and resources](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices) that were accessed.
1. Investigate the [users](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).

**Suggested remediation and steps for prevention:**

1. Follow the instructions in the [unsecure Kerberos delegation](/defender-for-identity/security-assessment-unconstrained-kerberos) security assessment.
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
    - Select the **Download details** button to view the Security Alert report Excel file, view the related network activities, and check if there's a difference between "StartTime" and "DomainControllerStartTime".

If the answer to the previous questions is **yes**, **Close** the security alert as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer and accessed resources](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. Investigate the [compromised user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).

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

1. Investigate the [domain controller](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. Check if Skeleton Key has affected your domain controllers.
1. Investigate the [users](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users) and [computers](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices) involved.

**Suggested remediation and prevention steps**

1. Reset the passwords of the compromised users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the domain controller.
    - Remove the malware. For more information, see [Skeleton Key Malware Analysis](https://www.virusbulletin.com/virusbulletin/2016/01/paper-digital-bian-lian-face-changing-skeleton-key-malware).
    - Look for users logged on around the same time as the suspicious activity occurred, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

## Suspicious additions to sensitive groups (external ID 2024)

**Description**

Attackers add users to highly privileged groups. Adding users is done to gain access to more resources, and gain persistency. This detection relies on profiling the group modification activities of users, and alerting when an abnormal addition to a sensitive group is seen. [!INCLUDE [Product short](includes/product-short.md)] profiles continuously.

For a definition of sensitive groups in [!INCLUDE [Product short](includes/product-short.md)], see [Working with the sensitive accounts](/defender-for-identity/entity-tags).

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




## See Also

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