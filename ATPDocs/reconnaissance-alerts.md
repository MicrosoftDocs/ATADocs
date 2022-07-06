---
title: Microsoft Defender for Identity reconnaissance phase security alerts
description: This article explains Microsoft Defender for Identity alerts issued when attacks, part of reconnaissance phase efforts, are detected against your organization.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Reconnaissance alerts

Typically, cyberattacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. [!INCLUDE [Product long](includes/product-long.md)] identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. **Reconnaissance**
1. [Compromised credentials](compromised-credentials-alerts.md)
1. [Lateral Movements](lateral-movement-alerts.md)
1. [Domain dominance](domain-dominance-alerts.md)
1. [Exfiltration](exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all [!INCLUDE [Product short](includes/product-short.md)] security alerts, see [Understanding security alerts](understanding-security-alerts.md). For information about **True positive (TP)**, **Benign true positive (B-TP)**, and **False positive (FP)**, see [security alert classifications](understanding-security-alerts.md#security-alert-classifications).

The following security alerts help you identify and remediate **Reconnaissance** phase suspicious activities detected by [!INCLUDE [Product short](includes/product-short.md)] in your network.

In this article, you'll learn how to understand, classify, remediate, and prevent the following types of attacks:

> [!div class="checklist"]
>
> - Account enumeration reconnaissance (external ID 2003)
> - Active Directory attributes reconnaissance (LDAP) (external ID 2210)
> - Network mapping reconnaissance (DNS) (external ID 2007)
> - Security principal reconnaissance (LDAP) (external ID 2038)
> - User and Group membership reconnaissance (SAMR) (external ID 2021)
> - User and IP address reconnaissance (SMB) (external ID 2012)

## Account enumeration reconnaissance (external ID 2003)

*Previous name:* Reconnaissance using account enumeration

**Description**

In account enumeration reconnaissance, an attacker uses a dictionary with thousands of user names, or tools such as KrbGuess in an attempt to guess user names in the domain.

**Kerberos**: Attacker makes Kerberos requests using these names to try to find a valid username in the domain. When a guess successfully determines a username, the attacker gets the **Preauthentication required** instead of **Security principal unknown** Kerberos error.

**NTLM**: Attacker makes NTLM authentication requests using the dictionary of names to try to find a valid username in the domain. If a guess successfully determines a username, the attacker gets the **WrongPassword (0xc000006a)** instead of **NoSuchUser (0xc0000064)** NTLM error.

In this alert detection, [!INCLUDE [Product short](includes/product-short.md)] detects where the account enumeration attack came from, the total number of guess attempts, and how many attempts were matched. If there are too many unknown users, [!INCLUDE [Product short](includes/product-short.md)] detects it as a suspicious activity. The alert is based on authentication events from sensors running on domain controller and AD FS servers.

**MITRE**

|Primary MITRE tactic  |[Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007/)  |
|---------|---------|
|MITRE attack technique  | [Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/)        |
|MITRE attack sub-technique | [Domain Account (T1087.002)](https://attack.mitre.org/techniques/T1087/002/)        |

**Learning period**

None

**TP, B-TP, or FP**

Some servers and applications query domain controllers to determine if accounts exist in legitimate usage scenarios.

To determine if this query was a **TP**, **BTP**, or **FP**, select the alert to get to its detail page:

1. Check if the source computer was supposed to perform this type of query. Examples of a **B-TP** in this case could be Microsoft Exchange servers or human resource systems.

1. Check the account domains.
    - Do you see additional users who belong to a different domain?  
     A server misconfiguration such as Exchange/Skype or ADSF can cause additional users that belong to different domains.
    - Look at the configuration of the problematic service to fix the misconfiguration.

    If you answered **yes** to the questions above, it's a **B-TP** activity. *Close* the security alert.

As the next step, look at the source computer:

1. Is there a script or application running on the source computer that could generate this behavior?
    - Is the script an old script running with old credentials?  
    If yes, stop and edit or delete the script.
    - Is the application an administrative or security script/application that is supposed to run in the environment?

      If you answered **yes** to previous question, *Close* the security alert and exclude that computer. It's probably a **B-TP** activity.

Now, look at the accounts:

Attackers are known to use a dictionary of randomized account names to find existing account names in an organization.

1. Do the non-existing accounts look familiar?
    - If the non-existing accounts look familiar, they may be disabled accounts or belong to employees who left the company.
    - Check for an application or script that checks to determine which accounts still exist in Active Directory.

      If you answered **yes** to one of the previous questions, *Close* the security alert, it's probably a **B-TP** activity.

1. If any of the guess attempts match existing account names, the attacker knows of the existence of accounts in your environment and can attempt to use brute force to access your domain using the discovered user names.
    - Check the guessed account names for additional suspicious activities.
    - Check to see if any of the matched accounts are sensitive accounts.

**Understand the scope of the breach**

1. Investigate the source computer
1. If any of the guess attempts match existing account names, the attacker knows of the existence of accounts in your environment, and can use brute force to attempt to access your domain using the discovered user names. Investigate the existing accounts using the [user investigation guide](investigate-a-user.md).
    > [!NOTE]
    > Examine the evidence to learn the authentication protocol used. If NTLM authentication was used, enable NTLM auditing of Windows Event 8004 on the domain controller to determine the resource server the users attempted to access.  
    > Windows Event 8004 is the NTLM authentication event that includes information about the source computer, user account, and server that the source user account attempted to access.  
    > [!INCLUDE [Product short](includes/product-short.md)] captures the source computer data based on Windows Event 4776, which contains the computer defined source computer name. Using Windows Event 4776 to capture this information, the information source field is occasionally overwritten by the device or software and only displays Workstation or MSTSC as the information source. In addition, the source computer might not actually exist on your network. This is possible because adversaries commonly target open, internet-accessible servers from outside the network and then use it to enumerate your users. If you frequently have devices that display as Workstation or MSTSC, make sure to enable NTLM auditing on the domain controllers to get the accessed resource server name. You should also investigate this server, check if it is opened to the internet, and if you can, close it.

1. When you learn which server sent the authentication validation, investigate the server by checking events, such as Windows Event 4624, to better understand the authentication process.

1. Check if this server is exposed to the internet using any open ports. For example, is the server open using RDP to the internet?

**Suggested remediation and steps for prevention**

1. Contain the source [computer](investigate-a-computer.md).
    1. Find the tool that performed the attack and remove it.
    1. Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised.
    1. Reset their passwords and enable MFA or, if you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Enforce [Complex and long passwords](/windows/device-security/security-policy-settings/password-policy) in the organization. Complex and long passwords provide the necessary first level of security against brute-force attacks. Brute force attacks are typically the next step in the cyber-attack kill chain following enumeration.

## Active Directory attributes reconnaissance (LDAP) (external ID 2210)

**Description**

Active Directory LDAP reconnaissance is used by attackers to gain critical information about the domain environment. This information can help attackers map the domain structure, as well as identify privileged accounts for use in later steps in their attack kill chain. Lightweight Directory Access Protocol (LDAP) is one of the most popular methods used for both legitimate and malicious purposes to query Active Directory.

**MITRE**

|Primary MITRE tactic  |[Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007/)  |
|---------|---------|
|MITRE attack technique  | [Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/), [Indirect Command Execution (T1202)](https://attack.mitre.org/techniques/T1202/), [Permission Groups Discovery (T1069)](https://attack.mitre.org/techniques/T1069/)        |
|MITRE attack sub-technique | [Domain Account (T1087.002)](https://attack.mitre.org/techniques/T1087/002/), [Domain Groups (T1069.002)](https://attack.mitre.org/techniques/T1069/002/)        |

**Learning period**

None

**TP, B-TP, or FP**

1. Select the alert to view the queries that were performed.
    - Check if the source computer is supposed to make these queries
        - If yes, close the security alert as an **FP**. If it's an ongoing activity, exclude the suspicious activity.
1. Select the source computer and go to its profile page.
    - Look for any unusual activities that occurred around the time of the queries such as the following types of search: logged in users, accessed resources, and other probing queries.
    - If Microsoft Defender for Endpoint integration is enabled, select its icon to further investigate the machine.
        - Look for unusual processes and alerts that occurred around the time of the queries
1. Check exposed accounts.
    - Look for unusual activities.

If you answered yes to questions 2 or 3, consider this alert a **TP** and follow the instructions in **Understand the scope of the breach**.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
1. Is the computer running a scanning tool that performs various of LDAP queries?
    - Investigate whether the specific queried users and groups in the attack are privileged or high-value accounts (that is, CEO, CFO, IT management, etc.). If so, look at other activities on the endpoint as well and monitor computers that the queried accounts are logged into, as they're probably targets for lateral movement.
1. Check the queries and their attributes, and determine if they were successful. Investigate each exposed group, search for suspicious activities made on the group or by member users of the group.
1. Can you see SAM-R, DNS, or SMB reconnaissance behavior on the source computer?

**Suggested remediation and steps for prevention**

1. Contain the source computer
    1. Find the tool that performed the attack and remove it.
    1. If the computer is running a scanning tool that performs a variety of LDAP queries, look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Reset the password if SPN resource access was made that runs under a user account (not machine account).

## Network-mapping reconnaissance (DNS) (external ID 2007)

*Previous name:* Reconnaissance using DNS

**Description**

Your DNS server contains a map of all the computers, IP addresses, and services in your network. This information is used by attackers to map your network structure and target interesting computers for later steps in their attack.

There are several query types in the DNS protocol. This [!INCLUDE [Product short](includes/product-short.md)] security alert detects suspicious requests, either requests using an AXFR (transfer)  originating from non-DNS servers, or those using an excessive number of requests.

**MITRE**

|Primary MITRE tactic  | [Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007) |
|---------|---------|
|MITRE attack technique  |   [Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/), [Network Service Scanning (T1046)](https://attack.mitre.org/techniques/T1046/), [Remote System Discovery (T1018)](https://attack.mitre.org/techniques/T1018/)     |
|MITRE attack sub-technique |  N/A       |

**Learning period**

This alert has a learning period of eight days from the start of domain controller monitoring.

**TP, B-TP, or FP**

1. Check if the source computer is a DNS server.

    - If the source computer **is** a DNS server, close the security alert as an **FP**.
    - To prevent future **FPs**, verify that UDP port 53 is **open** between the [!INCLUDE [Product short](includes/product-short.md)] sensor and the source computer.

Security scanners and legitimate applications can  generate DNS queries.

1. Check if this source computer is supposed to generate this type of activity?

    - If this source computer is supposed to generate this type of activity, **Close** the security alert and exclude the computer as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).

**Suggested remediation and steps for prevention**

**Remediation:**

- Contain the source computer.
  - Find the tool that performed the attack and remove it.
  - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA or, if you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).

**Prevention:**

It's important to preventing future attacks using AXFR queries by securing your internal DNS server.

- Secure your internal DNS server to prevent reconnaissance using DNS by disabling zone transfers or by [restricting zone transfers](/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee649273(v=ws.10)) only to specified IP addresses. Modifying zone transfers is one task among a checklist that should be addressed for [securing your DNS servers from both internal and external attacks](/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee649273(v=ws.10)).

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
1. Investigate the [source computer](investigate-a-computer.md).
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

## User and Group membership reconnaissance (SAMR) (external ID 2021)

*Previous name:* Reconnaissance using directory services queries

**Description**

User and group membership reconnaissance are used by attackers to map the directory structure and target privileged accounts for later steps in their attack. The Security Account Manager Remote (SAM-R) protocol is one of the methods used to query the directory to perform this type of mapping.
In this detection, no alerts are triggered in the first month after [!INCLUDE [Product short](includes/product-short.md)] is deployed (learning period). During the learning period, [!INCLUDE [Product short](includes/product-short.md)] profiles which SAM-R queries are made from which computers, both enumeration and individual queries of sensitive accounts.

**Learning period**

Four weeks per domain controller starting from the first network activity of SAMR against the specific DC.

**MITRE**

|Primary MITRE tactic  | [Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007) |
|---------|---------|
|MITRE attack technique  | [Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/), [Permission Groups Discovery (T1069)](https://attack.mitre.org/techniques/T1069/)        |
|MITRE attack sub-technique |  [Domain Account (T1087.002)](https://attack.mitre.org/techniques/T1087/002/), [Domain Group (T1069.002)](https://attack.mitre.org/techniques/T1069/002/)       |

**TP, B-TP, or FP**

1. Select the source computer to go to its profile page.
    - Is the source computer supposed to generate activities of this type?
      - If yes, *Close* the security alert and exclude that computer, as a  **B-TP** activity.
    - Check the user/s that performed the operation.
      - Do those users normally log into that source computer, or are they administrators that should be performing those specific actions?
    - Check the user profile, and their related user activities. Understand their normal user behavior and search for additional suspicious activities using the [user investigation guide](investigate-a-user.md).

      If you answered **yes** to the previous above, *Close* the alert as a **B-TP** activity.

**Understand the scope of the breach**

1. Check the queries that were performed, for example, Enterprise admins, or Administrator,  and determine if they were successful.
1. Investigate each exposed user using the user investigation guide.
1. Investigate the source computer.

**Suggested remediation and steps for prevention**

1. Contain the source computer.
1. Find and remove the tool that performed the attack.
1. Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA or, if you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Reset the source user password and enable MFA or, if you've configured the relevant high-risk user policies in Azure Active Directory Identity Protection, you can confirm the  user is compromised in the [Microsoft 365 Defender user page](/microsoft-365/security/defender/investigate-users).
1. Apply Network access and restrict clients allowed to make remote calls to SAM group policy.

## User and IP address reconnaissance (SMB) (external ID 2012)

*Previous name:* Reconnaissance using SMB Session Enumeration

### Description

Enumeration using Server Message Block (SMB) protocol enables attackers to get information about where users recently logged on. Once attackers have this information, they can move laterally in the network to get to a specific sensitive account.

In this detection, an alert is triggered when an SMB session enumeration is performed against a domain controller.

**MITRE**

|Primary MITRE tactic  | [Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007) |
|---------|---------|
|MITRE attack technique  | [Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/), [System Network Connections Discovery (T1049)](https://attack.mitre.org/techniques/T1049/)        |
|MITRE attack sub-technique |  [Domain Account (T1087.002)](https://attack.mitre.org/techniques/T1087/002/)       |

**TP, B-TP, or FP**

Security scanners and applications may legitimately query domain controllers for open SMB sessions.

1. Is this source computer supposed to generate activities of this type?
1. Is there some kind of security scanner running on the source computer?
    If the answer is yes, it's probably a B-TP activity. *Close* the security alert and exclude that computer.
1. Check the users that performed the operation.
    Are those users supposed to perform those actions?
    If the answer is yes, *Close* the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the source computer.
1. On the alert page, check if there are any exposed users. To further investigate each exposed user, check their profile. We recommend you begin your investigation with sensitive and high investigation priority users.

**Suggested remediation and steps for prevention**

1. Contain the source computer.
1. Find and remove the tool that performed the attack.

> [!NOTE]
> To disable any [!INCLUDE [Product short](includes/product-short.md)] security alert, contact support.

> [!div class="nextstepaction"]
> [Compromised credential alerts](compromised-credentials-alerts.md)

## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Investigate a user](investigate-a-user.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Compromised credential alerts](compromised-credentials-alerts.md)
- [Lateral movement alerts](lateral-movement-alerts.md)
- [Domain dominance alerts](domain-dominance-alerts.md)
- [Exfiltration alerts](exfiltration-alerts.md)
- [[!INCLUDE [Product short](includes/product-short.md)] SIEM log reference](cef-format-sa.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
