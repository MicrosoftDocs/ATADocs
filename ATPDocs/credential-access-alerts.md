---
title: Microsoft Defender for Identity credential access security alerts
description: This article explains Microsoft Defender for Identity alerts issued when credential access attacks are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Credential access alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance and discovery alerts](reconnaissance-discovery-alerts.md)
1. [Persistence and privilege escalation alerts](persistence-privilege-escalation-alerts.md)
1. **Credential access**
1. [Lateral movement alerts](lateral-movement-alerts.md)
1. [Other alerts](other-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Credential access** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network.

Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.

## Suspected Brute Force attack (LDAP) (external ID 2004)

*Previous name:* Brute force attack using LDAP simple bind

**Description**

In a brute-force attack, the attacker attempts to authenticate with many different passwords for different accounts until a correct password is found for at least one account. Once found, an attacker can log in using that account.

In this detection, an alert is triggered when [!INCLUDE [Product short](includes/product-short.md)] detects a massive number of simple bind authentications. This alert detects brute force attacks performed either *horizontally* with a small set of passwords across many users, *vertically* with a large set of passwords on just a few users, or any combination of the two options. The alert is based on authentication events from sensors running on domain controller and AD FS servers.

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006) |
|---------|---------|
|MITRE attack technique  |  [Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)       |
|MITRE attack sub-technique |  [Password Guessing (T1110.001)](https://attack.mitre.org/techniques/T1110/001/), [Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/)       |

**TP, B-TP, or FP**

It is important to check if any login attempts ended with successful authentication.

1. If any login attempts ended successfully, are any of the **Guessed accounts** normally used from that source computer?
    - Is there any chance these accounts failed because a wrong password was used?
    - Check with the user(s) if they generated the activity, (failed to login a few times and then succeeded).

        If the answer to the previous questions is **yes**,  **Close** the security alert as a B-TP activity.

1. If there are no **Guessed accounts**, check if any of the **Attacked accounts** are normally used from the source computer.
    - Check if there is a script running on the source computer with wrong/old credentials?

        If the answer to the previous question is **yes**, stop and edit, or delete the script. **Close** the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. On the alert page, check which users, if any, were guessed successfully. For each user that was guessed successfully, [check their profile](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users) to investigate further.

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Reset the passwords of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Enforce [complex and long passwords](/windows/device-security/security-policy-settings/password-policy) in the organization, it will provide the necessary first level of security against future brute-force attacks.
1. Prevent future usage of LDAP clear text protocol in your organization.

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

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. If there is a [source user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users), investigate.
1. Check which resources were accessed successfully and [investigate](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer
    - Find the tool that preformed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in the [KRBTGT account article](/windows/security/identity-protection/access-control/active-directory-accounts#krbtgt-account).
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and they will not work again until they are renewed or in some cases, the service is restarted. Plan carefully before performing the KRBTGT double reset, because it impacts all computers, servers and users in the environment.
1. Make sure all domain controllers with operating systems up to Windows Server 2012 R2 are installed with [KB3011780](https://www.microsoft.com/download/details.aspx?id=44978) and all member servers and domain controllers up to 2012 R2 are up-to-date with [KB2496930](https://support.microsoft.com/help/2496930/ms11-013-vulnerabilities-in-kerberos-could-allow-elevation-of-privileg). For more information, see [Silver PAC](/security-updates/SecurityBulletins/2011/ms11-013) and [Forged PAC](/security-updates/SecurityBulletins/2014/ms14-068).

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

    - If the answer is **yes**, and it shouldn't be running, fix the application configuration. This alert is a **B-TP** and can be **Closed**.
    - If the answer is **yes**, and it should always do this, **Close** the alert, and exclude that computer, it's probably a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. If a [source user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users) exists, investigate.

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. The stolen private key is never changed. Meaning the actor can always use the stolen key to decrypt protected data in the target domain. A methodological way to change this private key does not exist.
    - To create a key, use the current private key, create a key, and re-encrypt every domain master key with the new private key.

## Suspected Brute Force attack (Kerberos, NTLM) (external ID 2023)

*Previous name:* Suspicious authentication failures

**Description**

In a brute-force attack, the attacker attempts to authenticate with multiple passwords on different accounts until a correct password is found or by using one password in a large-scale password spray that works for at least one account. Once found, the attacker logs in using the authenticated account.

In this detection, an alert is triggered when many authentication failures occur using Kerberos, NTLM, or use of a password spray is detected. Using Kerberos or NTLM, this type of attack is typically committed either *horizontal*, using a small set of passwords across many users, *vertical* with a large set of passwords on a few users, or any combination of the two.

In a password spray, after successfully enumerating a list of valid users from the domain controller, attackers try ONE carefully crafted password against ALL of the known user accounts (one password to many accounts). If the initial password spray fails, they try again, utilizing a different carefully crafted password, normally after waiting 30 minutes between attempts. The wait time allows attackers to avoid triggering most time-based account lockout thresholds. Password spray has quickly become a favorite technique of both attackers and pen testers. Password spray attacks have proven to be effective at gaining an initial foothold in an organization, and for making subsequent lateral moves, trying to escalate privileges. The minimum period before an alert can be triggered is one week.

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006) |
|---------|---------|
|MITRE attack technique  |  [Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)       |
|MITRE attack sub-technique |  [Password Guessing (T1110.001)](https://attack.mitre.org/techniques/T1110/001/), [Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/)       |

**Learning period**

1 week

**TP, B-TP, or FP**

It is important to check if any login attempts ended with successful authentication.

1. If any login attempts ended successfully, check if  any of the **Guessed accounts** are normally used from that source computer.
    - Is there any chance these accounts failed because a wrong password was used?
    - Check with the user(s) if they generated the activity, (failed to login a fe times and then succeeded).

      If the answer to the questions above is **yes**,  **Close** the security alert as a B-TP activity.

1. If there are no **Guessed accounts**, check if any of the **Attacked accounts** are normally used from the source computer.
    - Check if there is a script running on the source computer with wrong/old credentials?
    - If the answer to the previous question is **yes**, stop and edit, or delete the script. **Close** the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the source computer.
1. On the alert page, check which, if any, users were guessed successfully.
    - For each user that was guessed successfully, [check their profile](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users) to investigate further.

    > [!NOTE]
    > Examine the evidence to learn the authentication protocol used. If NTLM authentication was used, enable NTLM auditing of Windows Event 8004 on the domain controller to determine the resource server the users attempted to access. Windows Event 8004 is the NTLM authentication event that includes information about the source computer, user account, and server that the source user account  attempted to access.
    > [!INCLUDE [Product short](includes/product-short.md)] captures the source computer data based on Windows Event 4776, which contains the computer defined source computer name. Using Windows Event 4776 to capture this information, the information source field is occasionally overwritten by the device or software and only displays Workstation or MSTSC as the information source. In addition, the source computer might not actually exist on your network. This is possible because adversaries commonly target open, internet-accessible servers from outside the network and then use it to enumerate your users. If you frequently have devices that display as Workstation or MSTSC, make sure to enable NTLM auditing on the domain controllers to get the accessed resource server name. You should also investigate this server, check if it is opened to the internet, and if you can, close it.

1. When you learn which server sent the authentication validation, investigate the server by checking events, such as Windows Event 4624, to better understand the authentication process.
1. Check if this server is exposed to the internet using any open ports.
    For example, is the server open using RDP to the internet?

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Reset the passwords of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Enforce [complex and long passwords](/windows/device-security/security-policy-settings/password-policy) in the organization, it will provide the necessary first level of security against future brute-force attacks.


## Security principal reconnaissance (LDAP) (external ID 2038)

**Description**

Security principal reconnaissance is used by attackers to gain critical information about the domain environment. Information that helps attackers map the domain structure, as well as identify privileged accounts for use in later steps in their attack kill chain. Lightweight Directory Access Protocol (LDAP) is one the most popular methods used for both legitimate and malicious purposes to query Active Directory. LDAP focused security principal reconnaissance is commonly used as the first phase of a Kerberoasting attack. Kerberoasting attacks are used to get a target list of Security Principal Names (SPNs), which attackers then attempt to get Ticket Granting Server (TGS) tickets for.

To allow [!INCLUDE [Product short](includes/product-short.md)] to accurately profile and learn legitimate users, no alerts of this type are triggered in the first 10 days following [!INCLUDE [Product short](includes/product-short.md)] deployment. Once the [!INCLUDE [Product short](includes/product-short.md)] initial learning phase is completed, alerts are generated on computers that perform suspicious LDAP enumeration queries or queries targeted to sensitive groups that using methods not previously observed.

**MITRE**

|Primary MITRE tactic  | [Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007)  |
|---------|---------|
|Secondary MITRE tactic    |[Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)         |
|MITRE attack technique  |  [Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/)     |
|MITRE attack sub-technique | [Domain Account (T1087.002)](https://attack.mitre.org/techniques/T1087/002/)        |

**Learning period**

15 days per computer, starting from the day of the first event, observed from the machine.

**TP, B-TP, or FP**

1. Select the source computer and go to its profile page.
    1. Is this source computer expected to generate this activity?
    1. If the computer and activity are expected, **Close** the security alert and exclude that computer as a **B-TP** activity.

**Understand the scope of the breach**

1. Check the queries that were performed (such as Domain admins, or all users in a domain) and determine if the queries were successful. Investigate each exposed group search for suspicious activities made on the group, or by member users of the group.
1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
    - Using the LDAP queries, check if any resource access activity occurred on any of the exposed SPNs.

**Suggested remediation and steps for prevention**

1. Contain the source computer
    1. Find the tool that performed the attack and remove it.
    1. Is the computer running a scanning tool that performs various LDAP queries?
    1. Look for users logged on around the same time as the activity occurred as they may also be compromised. Reset their passwords and enable MFA or, if you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Reset the password if SPN resource access was made that runs under a user account (not machine account).

**Kerberoasting specific suggested steps for prevention and remediation**

1. Reset the passwords of the compromised users and enable MFA or, if you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Require use of [long and complex passwords for users with service principal accounts](/windows/security/threat-protection/security-policy-settings/minimum-password-length).
1. [Replace the user account by Group Managed Service Account (gMSA)](/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview).

> [!NOTE]
> Security principal reconnaissance (LDAP) alerts are supported by [!INCLUDE [Product short](includes/product-short.md)] sensors only.

## Suspected Kerberos SPN exposure (external ID 2410)

**Description**

Attackers use tools to enumerate service accounts and their respective SPNs (Service principal names), request a Kerberos service ticket for the services, capture the Ticket Granting Service (TGS) tickets from memory and extract their hashes, and save them for later use in an offline brute force attack.

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)  |
|---------|---------|
|MITRE attack technique  | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)        |
|MITRE attack sub-technique |   [Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/)    |

**Learning period**

None

**TP, B-TP, or FP**

1. Check if the source computer is running an attack tool, such as PowerSploit or Rubeus.
    1. If yes, it is a true positive. Follow the instructions in **Understand the scope of the breach**.
    1. If the source computer is found running that type of application, and it should continue doing so, Close the security alert as a B-TP activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [exposed accounts](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users). Check for malicious activity or suspicious behavior for these accounts.
1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).

**Remediation:**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Reset the passwords of the exposed users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

## Suspected AS-REP Roasting attack (external ID 2412)

Attackers use tools to detect accounts with their *Kerberos preauthentication* disabled and send AS-REQ requests without the encrypted timestamp. In response they receive AS-REP messages with TGT data, which may be encrypted with an insecure algorithm such as RC4, and save them for later use in an offline password cracking attack (similar to Kerberoasting) and expose plaintext credentials.

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)  |
|---------|---------|
|MITRE attack technique  | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)        |
|MITRE attack sub-technique |   [AS-REP Roasting (T1558.004)](https://attack.mitre.org/techniques/T1558/004/)    |

**Learning period**

None

**TP, B-TP, or FP**

1. Check if the source computer is running an attack tool, such as PowerSploit or Rubeus.
    1. If yes, it is a true positive. Follow the instructions in **Understand the scope of the breach**.
    1. If the source computer is found running that type of application, and it should continue doing so, **Close** the security alert as a **B-TP** activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [exposed accounts](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users). Check for malicious activity or suspicious behavior for these accounts.
1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).

**Remediation:**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Enable Kerberos preauthentication. For more information about account attributes and how to remediate them, see [Unsecure account attributes](/defender-for-identity/security-assessment-unsecure-account-attributes).

## Suspicious modification of a sAMNameAccount attribute (CVE-2021-42278 and CVE-2021-42287 exploitation) (external ID 2419)

**Description**

An attacker can create a straightforward path to a Domain Admin user in an Active Directory environment that isn't patched. This escalation attack allows attackers to easily elevate their privilege to that of a Domain Admin once they compromise a regular user in the domain.

When performing an authentication using Kerberos, Ticket-Granting-Ticket (TGT) and the Ticket-Granting-Service (TGS) are requested from the Key Distribution Center (KDC). If a TGS was requested for an account that couldn't be found, the KDC will attempt to search it again with a trailing &dollar;.

When processing the TGS request, the KDC will fail its lookup for the requestor machine *DC1* the attacker created. Therefore, the KDC will perform another lookup appending a trailing &dollar;. The lookup will succeed. As a result, the KDC will issue the ticket using the privileges of *DC1$*.

Combining CVEs CVE-2021-42278 and CVE-2021-42287, an attacker with domain user credentials can leverage them for granting access as a domain admin.

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)  |
|---------|---------|
|MITRE attack technique  | [Access Token Manipulation (T1134)](https://attack.mitre.org/techniques/T1134),[Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068),[Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558)     |
|MITRE attack sub-technique | [Token Impersonation/Theft (T1134.001)](https://attack.mitre.org/techniques/T1134/001/)        |

**Learning period**

None
  
**TP, B-TP, or FP**

1. Check and investigate the source computer and its original usage.
1. Follow the instructions in **Understand the scope of the breach**.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
2. Investigate the target domain controller and identify activities that occurred after the attack.
  
**Remediation:**

1. Contain the source computer.

    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. If you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

## Honeytoken activity (external ID 2014)

*Previous name:* Honeytoken activity

**Description**

Honeytoken accounts are decoy accounts set up to identify and track malicious activity that involves these accounts. Honeytoken accounts should be left unused while having an attractive name to lure attackers (for example,
SQL-Admin). Any activity from them might indicate malicious behavior.

For more information on honeytoken accounts, see [Manage sensitive or honeytoken accounts](/defender-for-identity/entity-tags).

**MITRE**

|Primary MITRE tactic  | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006)  |
|---------|---------|
|Secondary MITRE tactic    | [Discovery](https://attack.mitre.org/tactics/TA0007)        |
|MITRE attack technique  | [Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/)        |
|MITRE attack sub-technique | [Domain Account (T1087.002)](https://attack.mitre.org/techniques/T1087/002/)        |

**TP, B-TP, or FP**

1. Check if the owner of the source computer used the Honeytoken account to authenticate, using the method described in the suspicious activity page (for example, Kerberos, LDAP, NTLM).

    If the owner of the source computer used the honeytoken account to authenticate, using the exact method described in the alert, *Close* the security alert, as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).
1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).

    > [!NOTE]
    > If the authentication was made using NTLM, in some scenarios, there may not be enough information available about the server the source computer tried to access. [!INCLUDE [Product short](includes/product-short.md)] captures the source computer data based on Windows Event 4776, which contains the computer defined source computer name.
    > Using Windows Event 4776 to capture this information, the source field for this information is occasionally overwritten by the device or software to display only Workstation or MSTSC. If you frequently have devices that display as Workstation or MSTSC, make sure to enable NTLM auditing on the relevant domain controllers to get the true source computer name.
    > To enable NTLM auditing, turn on Windows Event 8004 (NTLM authentication event that includes information about the source computer, user account, and the server the source machine tried to access).

**Suggested remediation and steps for prevention**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

## Suspected DCSync attack (replication of directory services) (external ID 2006)

*Previous name:* Malicious replication of directory services

**Description**

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with all other domain controllers. Given necessary permissions, attackers can initiate a replication request, allowing them to retrieve the data stored in Active Directory, including password hashes.

In this detection, an alert is triggered when a replication request is initiated from a computer that isn't a domain controller.

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

1. Investigate the source [computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices) and [user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).

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

## See also

- [Investigate assets](investigate-assets.md)
- [Understanding security alerts](understanding-security-alerts.md)
- [Manage security alerts](/defender-for-identity/manage-security-alerts)
- [[!INCLUDE [Product short](includes/product-short.md)] SIEM log reference](cef-format-sa.md)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
