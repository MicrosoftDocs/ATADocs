---
title: Microsoft Defender for Identity compromised credentials phase security alerts
description: This article explains the Microsoft Defender for Identity alerts issued when attacks typical of the compromised credentials phase are detected against your organization.
ms.date: 12/06/2022
ms.topic: conceptual
---

# Compromised credential alerts

Typically, cyber-attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets – such as sensitive accounts, domain administrators, and highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](reconnaissance-alerts.md)
1. **Compromised credential**
1. [Lateral Movements](lateral-movement-alerts.md)
1. [Domain dominance](domain-dominance-alerts.md)
1. [Exfiltration](exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Compromised credential** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network. In this article, you'll learn how to understand, classify, remediate and prevent the following types of attacks:

> [!div class="checklist"]
>
> - [Suspicious modification of a sAMNameAccount attribute (CVE-2021-42278 and CVE-2021-42287 exploitation) (external ID 2419)](#suspicious-modification-of-a-samnameaccount-attribute-cve-2021-42278-and-cve-2021-42287-exploitation-external-id-2419)
> - [Honeytoken activity (external ID 2014)](#honeytoken-activity-external-id-2014)
> - [Suspected Brute Force attack (Kerberos, NTLM) (external ID 2023)](#suspected-brute-force-attack-kerberos-ntlm-external-id-2023)
> - [Suspected Brute Force attack (LDAP) (external ID 2004)](#suspected-brute-force-attack-ldap-external-id-2004)
> - [Suspected Brute Force attack (SMB) (external ID 2033)](#suspected-brute-force-attack-smb-external-id-2033)
> - [Suspected Kerberos SPN exposure (external ID 2410)](#suspected-kerberos-spn-exposure-external-id-2410)
> - [Suspected Netlogon privilege elevation attempt (CVE-2020-1472 exploitation) (external ID 2411)](#suspected-netlogon-priv-elev-2411)
> - [Suspected AS-REP Roasting attack (external ID 2412)](#suspected-as-rep-roasting-attack-external-id-2412)
> - [Suspected WannaCry ransomware attack (external ID 2035)](#suspected-wannacry-ransomware-attack-external-id-2035)
> - [Suspected use of Metasploit hacking framework (external ID 2034)](#suspected-use-of-metasploit-hacking-framework-external-id-2034)
> - [Suspicious VPN connection (external ID 2025)](#suspicious-vpn-connection-external-id-2025)

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

## Suspected Brute Force attack (SMB) (external ID 2033)

*Previous name:* Unusual protocol implementation (potential use of malicious tools such as Hydra)

**Description**

Attackers use tools that implement various protocols such as SMB, Kerberos, and NTLM in non-standard ways. While this type of network traffic is accepted by Windows without warnings, [!INCLUDE [Product short](includes/product-short.md)] is able to recognize potential malicious intent. The behavior is indicative of brute force techniques.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008) |
|---------|---------|
|MITRE attack technique  |  [Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)       |
|MITRE attack sub-technique |  [Password Guessing (T1110.001)](https://attack.mitre.org/techniques/T1110/001/), [Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/)       |

**TP, B-TP, or FP**

1. Check if the source computer is running an attack tool such as Hydra.
    1. If the source computer is running an attack tool, this alert is a **TP**. Follow the instructions in **Understand the scope of the breach**.

Occasionally, applications implement their own NTLM or SMB stack.

1. Check if the source computer is running its own NTLM or SMB stack type of application.
    1. If the source computer is found running that type of application, and it should not continue to run, fix the application configuration as needed. **Close** the security alert as a **B-TP** activity.
    1. If the source computer is found running that type of application, and it should continue doing so, **Close** the security alert as a **B-TP** activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. Investigate the [source user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users)) (if there is a source user).

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer
    1. Find the tool that performed the attack and remove it.
    1. Search for users logged on around the time of the activity, as they may also be compromised.
    1. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Enforce [Complex and long passwords](/windows/security/threat-protection/security-policy-settings/password-policy) in the organization. Complex and long passwords provide the necessary first level of security against future brute-force attacks.
1. [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

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

<a name="suspected-netlogon-priv-elev-2411"></a>

## Suspected Netlogon privilege elevation attempt (CVE-2020-1472 exploitation) (external ID 2411)

Microsoft published [CVE-2020-1472](https://portal.msrc.microsoft.com/security-guidance/advisory/CVE-2020-1472) announcing that a new vulnerability exists that allows the elevation of privileges to the domain controller.

An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol ([MS-NRPC](/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f)), also known as *Netlogon Elevation of Privilege Vulnerability*.

**MITRE**

|Primary MITRE tactic  | [Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004)  |

**Learning period**

None

**TP, B-TP, or FP**

If the source computer is a domain controller (DC), failed or low certainty resolution can prevent [!INCLUDE [Product short](includes/product-short.md)] from being able to confirm its identification.

1. If the source computer is a domain controller, **Close** the alert as a **B-TP** activity.

1. If this source computer is supposed to generate this type of activity and is expected to continue generating this type of activity in the future, **Close** the security alert as a **B-TP** activity and exclude the computer to avoid additional benign alerts.

Otherwise, consider this alert a **TP** and follow the instructions in **Understand the scope of the breach**.

**Understand the scope of the breach**

1. Investigate [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices), check for malicious scripts or tools that made the connection to the DC.

1. Investigate the destination DC for any suspicious activities that happened after the vulnerability was used.

**Remediation:**

1. Patch all of your machines making sure to apply security updates.
1. Review [our guidance](https://support.microsoft.com/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc) on managing changes in Netlogon secure channel connection which relate to and can prevent this vulnerability.
1. Contain the source computer.
    - Find the tool that performed the attack and remove it.

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

## Suspected WannaCry ransomware attack (external ID 2035)

*Previous name:* Unusual protocol implementation (potential WannaCry ransomware attack)

**Description**

Attackers use tools that implement various protocols in non-standard ways. While this type of network traffic is accepted by Windows without warnings, [!INCLUDE [Product short](includes/product-short.md)] is able to recognize potential malicious intent. The behavior is indicative of techniques used by advanced ransomware, such as WannaCry.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)  |
|---------|---------|
|MITRE attack technique  |   [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)      |
|MITRE attack sub-technique |    N/A     |

**TP, B-TP, or FP**

1. Check if WannaCry is running on the source computer.

    - If WannaCry is running, this alert is a **TP**. Follow the instructions in **understand the scope of the breach**, above.

Occasionally, applications implement their own NTLM or SMB stack.

1. Check if the source computer is running its own NTLM or SMB stack type of application.
    1. If the source computer is found running that type of application, and it should not continue to run, fix the application configuration as needed. **Close** the security alert as a **B-TP** activity.
    1. If the source computer is found running that type of application, and it should continue doing so, **Close** the security alert as a **B-TP** activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. Investigate the [compromised user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).

**Suggested remediation and steps for prevention**

1. Contain the source computer.
    - [Remove WannaCry](https://support.microsoft.com/help/890830/remove-specific-prevalent-malware-with-windows-malicious-software-remo)
    - WannaCry can decrypt the data in the hands of some ransom software, but only if the user has not restarted or turned off the computer. For more information, see [WannaCry Ransomware](https://www.microsoft.com/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/)
    - Look for users logged on around the time of the activity, as they might also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Patch all of your machines, making sure to apply security updates.
    - [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

## Suspected use of Metasploit hacking framework (external ID 2034)

*Previous name:* Unusual protocol implementation (potential use of Metasploit hacking tools)

**Description**

Attackers use tools that implement various protocols (SMB, Kerberos, NTLM) in non-standard ways. While this type of network traffic is accepted by Windows without warnings, [!INCLUDE [Product short](includes/product-short.md)] is able to recognize potential malicious intent. The behavior is indicative of techniques such as use of the Metasploit hacking framework.

**MITRE**

|Primary MITRE tactic  | [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008)  |
|---------|---------|
|MITRE attack technique  |   [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/)      |
|MITRE attack sub-technique |    N/A     |

**TP, B-TP, or FP**

1. Check if the source computer is running an attack tool such as Metasploit or Medusa.

1. If yes, it is a true positive. Follow the instructions in **understand the scope of the breach**, above.

Occasionally, applications implement their own NTLM or SMB stack.

 1. Check if the source computer is running its own NTLM or SMB stack type of application.
    1. If the source computer is found running that type of application, and it should not continue to run, fix the application configuration as needed. **Close** the security alert as a **B-TP** activity.
    1. If the source computer is found running that type of application, and it should continue doing so, **Close** the security alert as a **B-TP** activity, and exclude that computer.

**Understand the scope of the breach**

1. Investigate the [source computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices).
1. If there is a source user, [investigate the user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users).

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Contain the source computer.
    1. Find the tool that performed the attack and remove it.
    1. Search for users logged on around the time of the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Reset the passwords of the source user and enable MFA or, if you have configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

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

> [!div class="nextstepaction"]
> [Lateral Movement alerts](lateral-movement-alerts.md)

## See Also

- [Investigate a computer](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-devices)
- [Investigate a user](/defender-for-identity/investigate-assets#investigation-steps-for-suspicious-users)
- [Working with security alerts](/defender-for-identity/manage-security-alerts)
- [Working with lateral movement paths](/defender-for-identity/understand-lateral-movement-paths)
- [Reconnaissance alerts](reconnaissance-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
