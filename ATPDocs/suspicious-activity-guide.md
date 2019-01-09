---
# required metadata

title: Azure ATP security alert guide | Microsoft Docs
d|Description: This article provides a list of the security alerts issued by Azure ATP and steps for remediation.
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 1/1/2019
ms.topic: conceptual
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: ca5d1c7b-11a9-4df3-84a5-f53feaf6e561

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




## Security alert name mapping and unique external ID

In version 2.56, all existing Azure ATP security alerts were renamed with easier to understand names. Mapping between old and new names, and their corresponding unique externalIds are as listed in the following table. Microsoft recommends use of alert externalIds in place of alert names for scripts or automation as only security alert externalIds are permanent and not subject to change.

> [!div class="mx-tableFixed"] 

|New security alert name|Previous security alert name|Unique externalId|
|---------|----------|---------|
|Account enumeration reconnaissance|Reconnaissance using account enumeration|2003|
|Data exfiltration over SMB| NA| 2030|
|Honeytoken activity|Honeytoken activity|2014|
|Malicious request of Data Protection API master key|Malicious Data Protection Private Information Request|2020|
|Network mapping reconnaissance (DNS)|Reconnaissance using DNS|2007|
|Remote code execution attempt|Remote code execution attempt|2019|
|Suspected brute force attack (LDAP)|Brute force attack using LDAP simple bind|2004|
|Suspected brute force attack (Kerberos, NTLM)|Suspicious authentication failures|2023|
|Suspected brute force attack (SMB)|Unusual protocol implementation (potential use of malicious tools such as Hydra)|2033|
|Suspected DCShadow attack (domain controller promotion)|Suspicious domain controller promotion (potential DCShadow attack)|2028|
|Suspected DCShadow attack (domain controller replication request)|Suspicious domain controller replication request (potential DCShadow attack)|2029|
|Suspected DCSync attack (replication of directory services)|Malicious replication of directory services|2006|
|Suspected Golden Ticket usage (encryption downgrade)|Encryption downgrade activity (potential golden ticket attack)|2009|
|Suspected Golden Ticket usage (forged authorization data) |Privilege escalation using forged authorization data|2013|
|Suspected Golden Ticket usage (nonexistent account)|Kerberos Golden Ticket - nonexistent account|2027|
|Suspected Golden Ticket usage (time anomaly) |Kerberos Golden Ticket - time anomaly|2022|
|Suspected Golden Ticket usage (ticket anomaly) - preview|NA|2032|
|Suspected identity theft (pass-the-hash)|Identity theft using Pass-the-Hash attack|2017|
|Suspected identity theft (pass-the-ticket)|Identity theft using Pass-the-Ticket attack|2018|
|Suspected over-pass-the-hash attack (encryption downgrade)|Encryption downgrade activity (potential overpass-the-hash attack)|2008|
|Suspected overpass-the-hash attack (Kerberos)|Unusual Kerberos protocol implementation (potential overpass-the-hash attack)|2002|
|Suspected use of Metasploit hacking framework|Unusual protocol implementation (potential use of Metasploit hacking tools)|2034|
|Suspected skeleton key attack (encryption downgrade)|Encryption downgrade activity (potential skeleton key attack)|2010|
|Suspected WannaCry ransomware attack|Unusual protocol implementation (potential WannaCry ransomware attack)|2035|
|Suspicious communication over DNS|Suspicious communication over DNS|2031|
|Suspicious modification of sensitive groups|Suspicious modification of sensitive groups|2024|
|Suspicious service creation|Suspicious service creation|2026|
|Suspicious VPN connection|Suspicious VPN connection|2025|
|User and group membership reconnaissance (SAMR)|Reconnaissance using directory services queries|2021|
|User and IP address reconnaissance (SMB) |Reconnaissance using SMB Session Enumeration|2012|

## Account enumeration reconnaissance (external ID 2003) <a name="reconnaissance-using-account-enumeration"></a>

*Previous name:* Reconnaissance using account enumeration

**Description**

In account enumeration reconnaissance, an attacker uses a dictionary with thousands of user names, or tools such as KrbGuess in an attempt to guess user names in the domain. The attacker makes Kerberos requests using these names in order to try to find a valid username in the domain. If a guess successfully determines a username, the attacker gets the Kerberos error **Preauthentication required** instead of **Security principal unknown**.

In this detection, Azure ATP detects where the account enumeration attack came from, the total number of guess attempts and how many attempts were matched. If there are too many unknown users, Azure ATP detects it as a suspicious activity.

**TP, B-TP, or FP**

Some servers and applications query domain controllers to determine if accounts exist in legitimate usage scenarios.

To determine if this query was a **TP**, **BTP** or **FP**, click on the alert to get to its detail page:

1. Check if the source computer was supposed to perform this type of query. Examples of a **B-TP** in this case could be Microsoft Exchange servers or human resource systems.

2. Check the account domains.
    - Do you see additional users who belong to a different domain? 
    <br>This can be caused by a server misconfiguration such as Exchange/Skype or ADSF.
    - Look at the configuration of the problematic service to fix the misconfiguration.

    If you answered **yes** to the questions above, it is a **B-TP** activity. *Close* the security alert.<br>

As the next step, look at the source computer: 

1. Is there a script or application running on the source computer that could generate this behavior?  
    - Is the script an old script running with old credentials? <br>If yes, stop and edit or delete the script. 
    - Is the application an administrative or security script/application that is supposed to run in the environment?
 
    If you answered **yes** to question above, *Close* the security alert and exclude that computer. It is probably a **B-TP** activity.

Now, look at the accounts:<br>
<br>Attackers are known to use a dictionary of randomized account names to find existing account names in an organization.

1. Do the non-existing accounts look familiar?  
    - If the non-existing accounts look familiar, they may be disabled accounts or belong to employees who left the company.
    - Check for an application or script that checks to determine which accounts still exist in Active Directory.

    If you answered **yes** to one of the questions above, *Close* the security alert, it is probably a **B-TP** activity.

2. If any of the guess attempts match existing account names, the attacker knows of the existence of accounts in your environment and can attempt to use brute force to access your domain using the discovered user names. 
    - Check the guessed account names for additional suspicious activities. 
    - Check to see if any of the matched accounts are sensitive accounts.

### Understand the scope of the breach

1. Investigate the source computer
2. If any of the guess attempts match existing account names, the attacker knows of the existence of accounts in your environment, and can use brute force to attempt to access your domain using the discovered user names. Investigate the existing accounts using the XYZ user investigation guide. 

### Suggested remediation and steps for prevention

1. Contain the source computer. 
    1. Find the tool that performed the attack and remove it.
    2. Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. 
    3. Reset their passwords and enable MFA.
2. Enforce [Complex and long passwords](https://docs.microsoft.com/windows/device-security/security-policy-settings/password-policy) in the organization. Complex and long passwords provide the necessary first level of security against brute-force attacks. Brute force attacks are typically the next step in the cyber-attack kill chain following enumeration.  

## Data exfiltration over SMB (external ID 2030)

Domain controllers hold the most sensitive organizational data. For most attackers, one of their top priorities is to gain access to your domain controllers, in order to steal your most sensitive data. For example, exfiltration of the Ntds.dit file, stored on a domain controller, allows an attacker to forge Kerberos ticket granting tickets(TGT) that provide authorization to any resource, and set the ticket expiration to any arbitrary time. *Data exfiltration over SMB alerts* are triggered when suspicious transfers of data are observed from your domain controllers.

**TP, B-TP, or FP**

1. Were the suspected users supposed to copy those specific files to the destination computer from the source computer?
    <br>If you answered yes to the question above,  *Close* the security alert and exclude that computer, it is probably a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source user(s)](xyz).  
2. Investigate the [source and destination computer(s)](xyz) of the copied file(s).

**Suggested remediation and steps for prevention**

1. Reset the source user passwords and enable MFA. 
2. Contain the source and destination computer.  
    1. Find the tool that performed the attack and remove it. 
    2. Find and remove the files that were copied. 
    3. Check if there were other actions done on the files. 
         - Where the files transferred to another place? 
         - Were the files transferred outside of the organizational network?
    4. Look for users logged on around the same time as the activity, as they may also be compromised. 
         - Reset their passwords and enable MFA.
1. If one of the files that was copied files was the ntds.dit file, do the following: 
    - Change the Kerberos Ticket Granting Ticket (KRBTGT) password two times in accordance with the [KRBTGT Account Password Reset guidance](), using the [Reset the KRBTGT account password/keys tool](). Resetting the KRBTGT password two times invalidates all of the Kerberos tickets in the domain. Invalidating all of the tickets means that all services will be broken, and will not work again until they are renewed or restarted as needed. **Note:** A KRBTGT Account Password Reset impacts all computers, servers and users in the environment, so plan accordingly before performing the reset.  
    - Close all existing sessions to the domain controllers.

## Honeytoken activity (external ID 2014) <a name="honeytoken-activity"></a>

*Previous name:* Honeytoken activity

**Description**

Honeytoken accounts are decoy accounts set up to identify and track malicious activity that involves these accounts. Honeytoken accounts should be left unused, while having an attractive name to lure attackers (for example,
SQL-Admin). Any activity from them might indicate malicious behavior.

For more information on honeytoken accounts, see [Configure detection exclusions and honeytoken accounts](install-atp-step7.md).

**TP, B-TP, or FP**

1. Check if the owner of the source computer used the Honeytoken account to authenticate, using the method described in the suspicious activity page (for example, Kerberos, LDAP, NTLM).

    If the owner of the source computer used the honeytoken account to authenticate using the method described in the alert, *Close* the security alert, as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source user](xyz).
2. Investigate the [source computer](xyz).

**Suggested remediation and steps for prevention**

1. Contain the source computer. 
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.

## Malicious request of Data Protection API master key (external ID 2020) <a name="malicious-data-protection-private-information-request"></a>

*Previous name:* Malicious Data Protection Private Information Request

**Description**

The Data Protection API (DPAPI) is used by Windows to securely protect passwords saved by browsers, encrypted files, and other sensitive data. Domain controllers hold a backup master key that can be used to decrypt all secrets encrypted with DPAPI on domain-joined Windows machines. Attackers can use the master key to decrypt any secrets protected by DPAPI on all domain-joined machines.
In this detection, an Azure ATP alert is triggered when the DPAPI is used to retrieve the backup master key.

**TP, B-TP, or FP?**

Advanced security scanners may legitimately generate this type of activity against Active Directory.

1. Check if the source computer is running an organization-approved advanced security scanner against Active Directory?

    - If the answer is **yes**, and it should not do this, fix the application configuration. This alert is a **B-TP** and can be **Closed**.
    - If the answer is **yes**, and it should always do this, **Close** the alert and exclude that computer, it is probably a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](xyz).
2. Investigate the [source user](xyz), if one exists. 

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA. 
2. Contain the source computer. 
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.
3. The stolen private key is never changed. This means the actor can always use the stolen key to decrypt protected data in the target domain. A methodological way to change this private key does not exist. 
    - To create a new key, use the current private key, create a new key and re-encrypt all of the domain master keys with the new private key.

## Network mapping reconnaissance (DNS) (external ID 2007)<a name="reconnaissance-using-dns"></a>

*Previous name:* Reconnaissance using DNS

**Description**

Your DNS server contains a map of all the computers, IP addresses, and services in your network. This information is used by attackers to map your network structure and target interesting computers for later steps in their attack. 
 
There are several query types in the DNS protocol. This Azure ATP security alert detects the AXFR (transfer) request originating from non-DNS servers.

**TP, B-TP, or FP**

1. Check if the source computer is a DNS server.

    - If the source computer **is** a DNS server, close the security alert as an **FP**. 
    - To prevent future **FPs**, verify that UDP port 53 is **open** between the Azure ATP sensor and the source computer.

Security scanners and legitimate applications can  generate DNS queries. 

1. Check if this source computer is supposed to generate this type of activity?

    - If this source computer is supposed to generate this type of activity, **Close** the security alert and exclude the computer as a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](XYZ). 

**Suggested remediation and steps for prevention**

**Remediation:**
1. Contain the source computer. 
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.

**Prevention:**
It is important to preventing future attacks using AXFR queries by securing your internal DNS server.

1. Secure your internal DNS server to prevent reconnaissance using DNS by disabling zone transfers or by [restricting zone transfers](https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee649273(v=ws.10)) only to specified IP addresses. Modifying zone transfers is one task among a checklist that should be addressed for [securing your DNS servers from both internal and external attacks](https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee649273(v=ws.10)).

## Remote code execution attempt (external ID 2019) <a name="remote-code-execution-attempt"></a>

*Previous name:* Remote code execution attempt

**Description**

Attackers who compromise administrative credentials or use a zero-day exploit can execute remote commands on your domain controller. This can be used for gaining persistency, collecting information, denial of service (DOS) attacks or any other reason. Azure ATP detects PSexec, Remote WMI, and PowerShell connections.

**TP, B-TP, or FP**

Administrative workstations, IT team members and service accounts can all perform legitimate administrative tasks against the domain controllers. 

1. Check if the source computer or user is supposed to run these types of commands on your domain controller?  
    - If the source computer or user is supposed to run these types of commands, **Close** the security alert as a **B-TP** activity. XYZ 
    - Is the source computer or user is supposed to run these commands on your domain controller, and will continue to do so, **Close** the security alert and exclude that computer, as a **B-TP** activity.

3. If the answer to either questions is no, then this should be considered a true positive. Try to find the source of the attempt by checking computer and account profiles. Click on the source computer or account to go to its profile page. Check what happened around the time of these attempts, searching for unusual activities, such as: who was logged in, which resources where accessed. If you enabled Windows Defender ATPintegration, click the Windows Defender ATP badge ![Windows Defender ATP badge](./media/wd-badge.png) to further investigate the machine. In Windows Defender ATPyou can see which processes and alerts occurred around the time of the alert. 

**Understand the scope of the breach**

1. Investigate the [source computer](xyz) and [user](xyz).
2. Investigate the [domain controller](xyz)

**Suggested remediation and prevention steps**

**Remediation**

1. Reset the password of the source users and enable MFA. 
2. Contain the domain controllers by:
    - Remediate the remote code execution attempt. 
    - Look for users logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA.  
3. Contain the source computer. 
    - Find the tool that performed the attack and remove it. 
    - Look for users logged on around the same time as the suspicious activity, as they may also be compromised. Reset their passwords and enable MFA. 

**Prevention**

1. Restrict remote access to domain controllers from non-Tier 0 machines. 
2. Implement [privileged access](https://technet.microsoft.com/windows-server-docs/security/securing-privileged-access/securing-privileged-access). allowing only hardened machines to connect to domain controllers for admins. 
3. Implement less-privileged access on domain machines to allow only specific users the right to create new services. 

> [!NOTE]
> Remote code execution attempt alerts are only supported by ATP sensors. 

## Suspected Brute Force attack (Kerberos, NTLM) (external ID 2023) <a name="suspicious-authentication-failures"></a>

*Previous name:* Suspicious authentication failures

**Description**

In a brute-force attack, the attacker attempts to authenticate with multiple passwords on different accounts until a correct password is found or by using one password in a large-scale password spray that works for at least one account. Once found, the attacker logs in using the authenticated account.

In this detection, an alert is triggered when many authentication failures occur using Kerberos, NTLM, or use of a password spray is detected. Using Kerberos or NTLM, this type of attack is typically committed either *horizontal*, using a small set of passwords across many users, *vertical* with a large set of passwords on a few users, or any combination of the two. 

In a password spray, after successfully enumerating a list of valid users from the domain controller, attackers try ONE carefully crafted password against ALL of the known user accounts (one password to many accounts). If the initial password spray fails, they try again, utilizing a different carefully crafted password, normally after waiting 30 minutes between attempts. The wait time allows attackers to avoid triggering most time-based account lockout thresholds. Password spray has quickly become a favorite technique of both attackers and pen testers. Password spray attacks have proven to be effective at gaining an initial foothold in an organization, and for making subsequent lateral moves, trying to escalate privileges. The minimum period before an alert can be triggered is one week.

**Learning period**
 <br>1 week.

**TP, B-TP, or FP**

It is important to check if any login attempts ended with successful authentication.

1. If any login attempts ended successfully, check if  any of the **Guessed accounts** are normally used from that source computer.
    - Is there any chance these accounts failed because a wrong password was used?  
    - Check with the user(s) if they generated the activity, (failed to login a fe times and then succeeded). 

    If the answer to the questions above is **yes**,  **Close** the security alert as a B-TP activity.

2. If there are no **Guessed accounts**, check if any of the **Attacked accounts** are normally used from the source computer.
    - Check if there is a script running on the source computer with wrong/old credentials?
    - If the answer to the previous question is **yes**, stop and edit, or delete the script. **Close** the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the source computer.  
2. On the alert page, check which, if any, users were guessed successfully. 
    - For each user that was guessed successfully, [check their profile](xyz) to investigate further.
3. If an alert occurs many times and the authentication was performed using NTLM, sometimes, there will not be enough information available about the server the source machine tried to access.
    1. To get this information, make sure to enable NTLM auditing on the domain controllers involved.  
    2. To enable NTLM auditing, turn on event 8004 (the NTLM authentication event that includes information about the source computer, user account and server that the source machine tried to access).
    3. When you learn which server sent the authentication validation, investigate the server by checking events, such as event 4624, to better understand the authentication process.

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA. 
2. Add the guessed users to a watchlist. 
3. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.
4. Reset the passwords of the source user and enable MFA.
5. Enforce [complex and long passwords](https://docs.microsoft.com/windows/device-security/security-policy-settings/password-policy) in the organization, it will provide the necessary first level of security against future brute-force attacks.

## Suspected Brute Force attack (LDAP) (external ID 2004) <a name="brute-force-attack-using-ldap-simple-bind"></a>

*Previous name:* Brute force attack using LDAP simple bind

### **Description**

In a brute-force attack, the attacker attempts to authenticate with many different passwords for different accounts until a correct password is found for at least one account. Once found, an attacker can log in using that account.  
In this detection, an alert is triggered when Azure ATP detects a massive number of simple bind authentications. This alert detects brute force attacks performed either *horizontally* with a small set of passwords across many users, *vertically* with a large set of passwords on just a few users, or any combination of the two options. 

**TP, B-TP, or FP**

It is important to check if any login attempts ended with successful authentication.

1. If any login attempts ended successfully, are any of the **Guessed accounts** normally used from that source computer?
    - Is there any chance these accounts failed because a wrong password was used?  
    - Check with the user(s) if they generated the activity, (failed to login a few times and then succeeded). 

    If the answer to the previous questions is **yes**,  **Close** the security alert as a B-TP activity. 

2. If there are no **Guessed accounts**, check if any of the **Attacked accounts** are normally used from the source computer.
    - Check if there is a script running on the source computer with wrong/old credentials?

    If the answer to the previous question is **yes**, stop and edit, or delete the script. **Close** the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the source computer.  
2. On the alert page, check which users, if any, were guessed successfully. For each user that was guessed successfully, [check their profile](xyz) to investigate further.

**Suggested remediation and steps for prevention**

1. Reset the passwords of the guessed users and enable MFA.
2. Add the guessed users to a watchlist.
3. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.
4. Reset the passwords of the source user and enable MFA.
5. Enforce [complex and long passwords](https://docs.microsoft.com/windows/device-security/security-policy-settings/password-policy) in the organization, it will provide the necessary first level of security against future brute-force attacks.
6. Prevent future usage of LDAP clear text protocol in your organization.

## Suspected DCShadow attack (domain controller promotion) (external ID 2028) <a name="suspicious-domain-controller-promotion-potential-dcshadow-attack"></a>

*Previous name:* Suspicious domain controller promotion (potential DCShadow attack)

**Description**

A domain controller shadow (DCShadow) attack is an attack designed to change directory objects using malicious replication. This attack can be performed from any machine by creating a rogue domain controller using a replication process.

In a DCShadow attack, RPC and LDAP are used to:

1. Register the machine account as a domain controller (using domain admin rights).
2. Perform replication (using the granted replication rights) over DRSUAPI and send changes to directory objects.

In this Azure ATP detection, a security alert is triggered when a machine in the network tries to register as a rogue domain controller.

**TP, B-TP, or FP**

Failed or low certainty resolution can prevent Azure ATP from identifying if the source computer is a domain controller.  

1. Check if the source computer is a domain controller?
    If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Changes in your Active Directory can take time to synchronize.

1. Is the source computer a newly promoted domain controller? If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Servers and applications might replicate data from Active Directory, such as Azure AD Connect or network performance monitoring devices. 

1. Check if this source computer is supposed to generate this type of activity?

    - If the answer is **yes**, but the source computer should not continue generating this type of activity in the future, fix the configuration of the server/application. **Close** the security alert as a  **B-TP** activity.

    - If the answer is **yes** and the source computer should continue generating this type of activity in the future, **Close** the security alert as a **B-TP** activity, and exclude the computer to avoid additional benign alerts.

**Understand the scope of the breach**

1. Investigate the [source computer](xyz).
2. Look at the Event Viewer to see [Active Directory events that it records in the directory services log](https://docs.microsoft.com/previous-versions/windows/it-pro/windows-2000-server/cc961809(v=technet.10)/). You can use the log to monitor changes in Active Directory. By default, Active Directory only records critical error events, but if this alert recurs, enable this audit on the relevant domain controller for further investigation.

**Suggested remediation and steps for prevention:**

**Remediation:**

1. Contain the source computer.
2. Find the tool that performed the attack and remove it.
3. Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
2. Replicate directory changes all.
3. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx). You can leverage [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a Windows PowerShell script to determine who in the domain has these permissions.

> [!NOTE]
> Suspicious domain controller promotion (potential DCShadow attack) alerts are supported by ATP sensors only.

## Suspected DCShadow attack (domain controller replication request) (external ID 2029) <a name="suspicious-replication-request-potential-dcshadow-attack"></a>

*Previous name:* Suspicious replication request (potential DCShadow attack)

**Description**

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with other domain controllers. Given necessary permissions, attackers can grant rights for their machine account, allowing them to impersonate a domain controller. The attackers will strive to initiate a malicious replication request, allowing them to change Active Directory objects on a genuine domain controller, which might give the attackers persistence in the domain.
In this detection, an alert is triggered when a suspicious replication request is generated against a genuine domain controller protected by Azure ATP. The behavior is indicative of techniques used in domain controller shadow attacks.

**TP, B-TP, or FP** 

Failed or low certainty resolution can prevent Azure ATP from identifying if the source computer is a domain controller.  

1. Check if the source computer is a domain controller?
    If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Changes in your Active Directory can take time to synchronize.

1. Is the source computer a newly promoted domain controller? If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Servers and applications might replicate data from Active Directory, such as Azure AD Connect or network performance monitoring devices.

1. Was this source computer supposed to generate this type of activity?

    - If the answer is **yes**, but the source computer should not continue generating this type of activity in the future, fix the configuration of the server/application. **Close** the security alert as a  **B-TP** activity.

    - If the answer is **yes**, and the source computer should continue generating this type of activity in the future, **Close** the security alert as a **B-TP** activity, and exclude the computer to avoid additional benign alerts.

**Understand the scope of the breach**

1. Investigate the source computer. 

**Suggested remediation and steps for prevention**

**Remediation:**

1. Contain the source computer.
2. Find the tool that performed the attack and remove it.
3. Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.
4. Remediate the data that was replicated on the domain controllers.

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
2. Replicate directory changes all.
3. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx). You can leverage [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a Windows PowerShell script to determine who in the domain has these permissions.

> [!NOTE]
> Suspicious replication request (potential DCShadow attack) alerts are supported by ATP sensors only. 

## Suspected DCSync attack (replication of directory services) (external ID 2006) <a name="malicious-replication-of-directory-services"></a>

*Previous name:* Malicious replication of directory services

**Description**

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with all other domain controllers. Given necessary permissions, attackers can initiate a replication request, allowing them to retrieve the data stored in Active Directory, including password hashes.

In this detection, an alert is triggered when a replication request is initiated from a computer that is not a domain controller.

> [!NOTE]
> If you have domain controllers on which Azure ATP sensors are not installed, those domain controllers are not covered by Azure ATP. In this case, if you deploy a new domain controller on an unregistered or unprotected domain controller, it may not be identified by Azure ATP as a domain controller at first. It is highly recommended to install the Azure ATP sensor on every domain controller to get full coverage.

**TP, B-TP, or FP**

Failed or low certainty resolution can prevent Azure ATP from identifying if the source computer is a domain controller.  

1. Check if the source computer is a domain controller?
    If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Changes in your Active Directory can take time to synchronize.

1. Is the source computer a newly promoted domain controller? If the answer is **yes**, **Close** the alert as a **B-TP** activity.

Servers and applications might replicate data from Active Directory, such as Azure AD Connect or network performance monitoring devices.

1. Was this source computer was supposed to generate this type of activity?

    - If the answer is **yes**, but the source computer should not continue to generate this type of activity in the future, fix the configuration of the server/application. **Close** the security alert as a  **B-TP** activity.

    - If the answer is **yes**, and the source computer should continue to generate this type of activity in the future, **Close** the security alert as a **B-TP** activity, and exclude the computer to avoid additional benign alerts.

**Understand the scope of the breach**

1. Investigate the source [computer](xyz) and [user](xyz). 

**Suggested remediation and steps for prevention**

**Remediation:**

1. Reset the password of the source users and enable MFA.
2. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
2. Replicate directory changes all.
3. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx). You can leverage [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a Windows PowerShell script to determine who in the domain has these permissions.


**Remediation**

Validate the following permissions: 

- Replicate directory changes   

- Replicate directory changes all  

For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx).
You can leverage [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a Windows PowerShell script to determine who in the domain has these permissions.

## Suspected Golden Ticket usage (encryption downgrade)
<a name="Encryption-downgrade-activity-potential-golden-ticket-attack"></a>

*Previous name:* Encryption downgrade activity

**Description**
Encryption downgrade is a method of weakening Kerberos by downgrading the encryption level of different fields of the protocol that are encrypted using the highest level of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, Azure ATP learns the Kerberos encryption types used by computers and users, and alerts you when a weaker cypher is used that: (1) is unusual for the source computer and/or user; and (2) matches known attack techniques. 

In a Golden Ticket alert, the encryption method of the ticket granting ticket (TGT) field of TGS_REQ (service request) message from the source computer was downgraded compared to the previously learned behavior. This is not based on a time anomaly (as in the other Golden Ticket detection). In addition, there was no Kerberos authentication request associated with the previous service request detected by ATP.

**Investigation**

1. Some resources don’t support strong encryption methods and might trigger this alert.
   1. Check the resources accessed by those tickets. Check this in Active Directory by checking the attribute *msDS-SupportedEncryptionTypes*, of the resource service account.
   2. If there is one resource that is being accessed, validate it. Make sure it is a valid resource they're supposed to access.
2. Custom applications might authenticate using a lower encryption cipher.
   1. Check if there are any custom apps authenticating using a lower encryption cipher on the source computer.
   2. If there are multiple users, check if they have something in common. <br>For example, all of your marketing personnel using a specific app that might be triggering the alert.
3. Click on the source computer or account to go to its profile page. Check what happened around the time of the replication. Make sure to searching for unusual activities, such as who was logged in, and which resources where accessed. 

4. If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge ![Windows Defender ATP badge](./media/wd-badge.png) to further investigate the machine. In Windows Defender ATP, you can see which processes and alerts occurred around the time of the alert.

**Remediation**

1. Reset the password for the compromised users.
2. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain, so plan carefully before performing the reset.

## Suspected Golden Ticket usage (forged authorization data)
<a name="privilege-escalation-using-forged-authorization-data"></a>

*Previous name:* Privilege escalation using forged authorization data

**Description**

Known vulnerabilities in older versions of Windows Server allow attackers to manipulate the Privileged Attribute Certificate (PAC). The PAC is a field in the Kerberos ticket that contains user authorization data (in Active Directory this is group membership), granting attackers additional privileges.

**Investigation**

1. Click on the alert to get to its details page.

2. Is the destination computer (under the **ACCESSED** column) patched with MS14-068 (domain controller) or MS11-013 (server)? If yes, **Close** the suspicious activity (it is a false positive).

3. If not, does the source computer run (under the **FROM** column) an OS/application known to modify the PAC? If yes, **Suppress** the suspicious activity (it is a benign true positive).

4. If the answer was no to the above two questions, assume this is malicious.

**Remediation**

Make sure all domain controllers with operating systems up to Windows Server 2012 R2 are installed with [KB3011780](https://support.microsoft.com/help/2496930/ms11-013-vulnerabilities-in-kerberos-could-allow-elevation-of-privilege) and
all member servers and domain controllers up to 2012 R2 are up-to-date with KB2496930. For more information, see [Silver PAC](https://technet.microsoft.com/library/security/ms11-013.aspx) and [Forged PAC](https://technet.microsoft.com/library/security/ms14-068.aspx).

## Suspected Golden Ticket usage (nonexistant account)
<a name="golden-ticket"></a>

Previous name: Kerberos golden ticket

**Description**

Attackers that gain domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, attackers can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource. A forged TGT of this type is called a "Golden Ticket" because it allows attackers to achieve lasting network persistence. In this detection, an alert is triggered by use of a nonexistent account.

**Investigation**

1. Ask the following questions:
      - Is the user a known and valid domain user? If yes, then Close the alert (it was a false positive).
      - Has the user been recently added? If yes, then Close the alert, the change may not have been synchronized yet.
      - Has the user been recently deleted from AD? If yes, then Close the alert.
2. If the answer to the above questions is no, assume this is malicious.

3. Click on the source computer to go to its **Profile** page. Check what happened around the time of the activity and look for unusual activities including who was logged in, which resources were accessed? 

4. Are all the users who were logged into the computer supposed to be logged into? What are their privileges? 

5. Are the users who were logged in supposed to have access to these resources?<br>
If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge.
 
 1. To further investigate the machine, check which processes and alerts occurred around the time of the alert in Windows Defender ATP.

**Remediation**


Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys
tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain so plan before doing so. Also, because creating a Golden Ticket requires domain admin rights, implement [Pass the hash recommendations](https://www.microsoft.com/download/details.aspx?id=36036).

## Suspected Golden Ticket usage (time anomaly)

Previous name: Kerberos golden ticket

**Description**

Attackers that gain domain admin rights can compromise the [KRBTGT account](https://technet.microsoft.com/library/dn745899(v=ws.11).aspx#Sec_KRBTGT). Using the KRBTGT account, attackers can create Kerberos ticket granting tickets (TGT) that provide authorization to any resource, and set the ticket expiration to any arbitrary time. A forged TGT of this type is called a "Golden Ticket"  because it allows attackers to achieve lasting network persistence. In this detection, an alert is triggered when a Kerberos ticket granting ticket is used for more than the allowed time permitted, as specified in the [Maximum lifetime for user ticket](https://technet.microsoft.com/library/jj852169(v=ws.11).aspx).


**Investigation**

1. Was there any recent (within the last few hours) change made to the Maximum lifetime for user ticket setting in group policy? Check for the specific value and see if it is lower than the time the ticket was used for. If yes, then Close the alert (it was a false positive).

2. Is the Azure ATP sensor involved in this alert a virtual machine? If yes, did it recently resume from a saved state? If yes, then Close this alert.

3. If the answer to the above questions is no, assume this is malicious.

**Remediation**


Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys
tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain so plan before doing so. Also, because creating a Golden Ticket requires domain admin rights, implement [Pass the hash recommendations](https://www.microsoft.com/download/details.aspx?id=36036).

## Suspected Golden Ticket usage (ticket anomaly) - preview
<a name="golden-ticket-usage-ticket-anomaly
"></a>

**Description**

Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource. A forged TGT of this type is called a "Golden Ticket" because it allows attackers to achieve lasting network persistence. Forged Golden Tickets of this type have unique characteristics this detection is designed to identify. 

**Investigation**
1. Federation services might generate tickets that will trigger this alert. Does the source computer host such services? If yes, Close the security alert.
2. Click on the source user to go to their profile page. Check what happened around the time of the activity.
      1. Is the user supposed to have access (is it allowed), to this resource? 
      2. Is the principal expected to access that service? 
3. Click on the source computer to go to their Profile page. Check what happened around the time of the activity and look for unusual activities including who was logged in, and which resources were accessed?
4. Are all the users who logged into the computer supposed to be logged into the computer? What are their privileges?
5. Are the users who logged in supposed to have access to the resources they logged into?
<br>If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge.
6. To further investigate the machine, check which processes and alerts occurred around the time of the alert in Windows Defender ATP.


**Remediation**

Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys
tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain,  so plan carefully before doing so. Also, because creating a Golden Ticket requires domain admin rights, implement [Pass the hash recommendations](https://www.microsoft.com/download/details.aspx?id=36036).

## Suspected identity theft (pass-the-hash) 
<a name="identity-theft-using-pass-the-hash-attack"></a>

*Previous name:* Identity theft using Pass-the-Hash attack

**Description**

Pass-the-Hash is a lateral movement technique in which attackers steal a user’s NTLM hash from one computer and use it to gain access to another computer. 

**Investigation**

Investigate if the hash was used from a computer that the targeted user owns or regularly uses? If yes, this is a false positive, if not, it is probably a true positive.

**Remediation**

1. If the involved account is not sensitive, then reset the password of that account. This prevents the attacker from creating new Kerberos tickets from the password hash, although the existing tickets can still be used until they
expire. 

2. If it’s a sensitive account, you should consider resetting the KRBTGT account twice. Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain so plan before doing so. See
the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), also see using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). Since this is a lateral movement technique, follow the best practices of [Pass the hash recommendations](https://www.microsoft.com/download/details.aspx?id=36036).

## Suspected identity theft (pass-the-ticket) 
<a name="identity-theft-using-pass-the-ticket-attack"></a>

*Previous name:* Identity theft using Pass-the-Ticket attack

**Description**

Pass-the-Ticket is a lateral movement technique in which attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by reusing the stolen ticket. In this detection, a Kerberos ticket is seen used on two (or more) different computers.

**Investigation**

1. Click the **Download details** button to view the full list of IP addresses involved. Does the IP address of one or both computers belong to a subnet that is allocated from an undersized DHCP pool, for example, VPN or WiFi? Is the IP address shared? For example, by a NAT device? Are one or more of the source IP addresses not being resolved by the sensor? (this could indicate that the proper ports from the sensor to the devices are not properly opened.) If the answer to any of these questions is yes, then it is a false positive.

2. Is there a custom application that forwards tickets on behalf of users? If so, it is a benign true positive.

**Remediation**

1. If the involved account is not sensitive, then reset the password of that account. This prevents the attacker from creating new Kerberos tickets from the password hash, although the existing tickets can still be used until they expire.  

2. If it’s a sensitive account, you should consider resetting the KRBTGT account twice. Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain so plan before doing so. See the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), also see using the [Reset the KRBTGT account password/keys
tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51).  Since this is a lateral movement technique, follow the best practices in [Pass the hash recommendations](https://www.microsoft.com/download/details.aspx?id=36036).

## Suspected Over-Pass-the-Hash attack (encryption downgrade) 
<a name="Encryption-downgrade-activity-potential-over-pass-the-hash"></a>

*Previous name:* Encryption downgrade activity

**Description**

Encryption downgrade is a method of weakening Kerberos by downgrading the encryption level of different fields of the protocol that are encrypted using the highest level of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, Azure ATP learns the Kerberos encryption types used by computers and users, and alerts you when a weaker cypher is used that: (1) is unusual for the source computer and/or user; and (2) matches known attack techniques. 

In an over-pass-the-hash attack, an attacker can use a weak stolen hash in order to create a strong ticket, with a Kerberos AS request. In this detection, the AS_REQ message encryption type from the source computer was downgraded compared to the previously learned behavior (that is, the computer was using AES).

**Investigation**

1. Was the smartcard configuration changed recently? <br>Check if there were changes like this for the account(s) involved. If so, this is probably a benign true positive and can be suppressed.
2. Some resources don’t support strong encryption methods. Weak encryption methods can trigger this alert.<br>Check the resources accessed by those tickets. Check this in Active Directory by checking the attribute *msDS-SupportedEncryptionTypes*, of the resource service account.<br>If there is one resource that is being accessed, validate it. Make sure it is a valid resource they're supposed to access. 
3. Click on the source computer or account to go to its profile page. Check what happened around the time of the replication, searching for unusual activities, such as who was logged in, and which resources where accessed. <br> If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge ![Windows Defender ATP badge](./media/wd-badge.png) to further investigate the machine. In Windows Defender ATP, you can see which processes and alerts occurred around the time of the alert.


**Remediation**
1. If the compromised user is *not sensitive* - reset the password of that account. This prevents the attacker from creating new Kerberos tickets from the password hash, although the existing tickets can still be used until they expire. 
2. If the compromised user is *sensitive* - consider resetting the KRBTGT account twice. Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain, so plan carefully before performing the reset. See guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/). Also see using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51).

## Suspected Skeleton Key attack (encryption downgrade) 
<a name="encryption-downgrade-activity-potential-skeleton-key-attack"></a>

*Previous name:* Encryption downgrade activity

**Description**
Encryption downgrade is a method of weakening Kerberos by downgrading the encryption level of different fields of the protocol that are encrypted using the highest level of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, Azure ATP learns the Kerberos encryption types used by computers and users, and alerts you when a weaker cypher is used that: (1) is unusual for the source computer and/or user; and (2) matches known attack techniques. 

Skeleton Key is malware that runs on domain controllers and allows authentication to the domain with any account without knowing its password. This malware often uses weaker encryption algorithms to hash the user's passwords on the domain controller. In this detection, the encryption method of the KRB_ERR message from the domain controller to the account asking for a ticket was downgraded compared to the previously learned behavior.

**Investigation**
1. Click on the source computer or account to go to its profile page. <br>Check what happened around the time of the replication, searching for unusual activities, such as who was logged in and which resources where accessed. <br>If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge ![Windows Defender ATP badge](./media/wd-badge.png) to further investigate the machine. In Windows Defender ATP, you can see which processes and alerts occurred around the time of the alert. 
2. Check if Skeleton Key has affected your domain controllers by using the [scanner written by the Azure ATP team](https://gallery.technet.microsoft.com/Aorato-Skeleton-Key-24e46b73).


**Remediation**
1. Remove the malware. For more information about malware removal, see [Skeleton Key Malware Analysis](https://www.virusbulletin.com/virusbulletin/2016/01/paper-digital-bian-lian-face-changing-skeleton-key-malware).


## Network-mapping reconnaissance (DNS)
<a name="reconnaissance-using-dns"></a>

Reconnaissance using DNS

**Description**

Your DNS server contains a map of all the computers, IP addresses, and services in your network. This information is used by attackers to map your network structure and target interesting computers for later steps in their attack.

There are several query types in the DNS protocol. Azure ATP detects the AXFR (Transfer) request originating from non-DNS servers.

**Investigation**

1. Is the source machine (**Originating from…**) a DNS server? If yes, then this is probably a false positive. To validate, click on the alert to get to its details page. In the table, under **Query**, check which domains were queried. Are these existing domains? If yes, then **Close** the suspicious activity (it is a false positive). In addition, make sure UDP port 53 is open between Azure ATP standalone sensor and the source computer to prevent future false positives.

2. Is the source machine running a security scanner? If yes, **Exclude the entities** in ATP, either directly with **Close and exclude** or via the **Exclusion** page (under **Configuration** – available for Azure ATP admins).

3. If the answer to all the preceding questions is no, keep investigating focusing on the source computer. Click on the source computer to go to its profile page. Check what happened around the time of the request, searching for unusual activities, such as: who was logged in, which resources where accessed. If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge ![Windows Defender ATP badge](./media/wd-badge.png) to further investigate the machine. In Windows Defender ATP, you can see which processes and alerts occurred around the time of the alert. 

**Remediation**

Securing an internal DNS server to prevent reconnaissance using DNS from occurring can be accomplished by disabling or restricting zone transfers only to specified IP addresses. For more information on restricting zone transfers, see [Restrict Zone Transfers](https://technet.microsoft.com/library/ee649273(v=ws.10).aspx).
Modifying zone transfers is one task among a checklist that should be addressed for [securing your DNS servers from both internal and external attacks](https://technet.microsoft.com/library/cc770432(v=ws.11).aspx).



## Suspicious communication over DNS <a name="suspicious-communication-over-dns"></a>

*Previous name:* Suspicious communication over DNS 



**Description**

The DNS protocol in most organizations is typically not monitored and rarely blocked for malicious activity. This enables an attacker on a compromised machine to abuse the DNS protocol. Malicious communication over DNS can be used for data exfiltration, command, and control, and/or evading corporate network restrictions.

**Is it a TP, B-TP or FP?** 
Some companies legitimately use DNS for regular communication. To determine the alert status: 

1. Check if the registered query domain belongs to a trusted source, such as your antivirus provider.  
    - If the domain is known and trusted, and DNS queries are permitted, it is a B-TP activity. *Close* the security alert, and exclude the domain from future alerts.  
    -  If the registered query domain is not trusted, identify the process creating the request on the source computer. Use [Process Monitor](https://docs.microsoft.com/sysinternals/downloads/procmon) to assist with this task. 

**Understand the scope of the breach**

1. On the destination computer, (supposed to be a DNS server), check for the records of the domain in question. What IP is it correlated to? Who is the owner of the domain? Where is the IP?
2. Investigate the source and destination computers. 

**Suggested remediation and steps for prevention**

1. Contain the source computer.
2. Find the tool that performed the attack and remove it.
3. Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA.
4. If, after your investigation, the  registered query domain is not trusted, we recommend blocking the destination domain to avoid all future communication.

**Investigation**
> [!NOTE]
> *Suspicious communication over DNS* security alerts list the suspected domain. New domains, or domains recently added that are not yet known or recognized by Azure ATP but are known to or part of your organization can be closed.


1. Some legitimate companies use DNS for regular communication. Check if the registered query domain belongs to a trusted source such as your antivirus provider. If the domain is known and trusted and DNS queries are permitted, the alert can be closed, and the domain can be [excluded](excluding-entities-from-detections.md) from future alerts.
2. If the registered query domain is not trusted, identify the process creating the request on the source machine. Use [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) to assist with this task.
3. Determine when the suspicious activity started? Were any new programs deployed or installed (AV?) in the organization? Are there other alerts from the same time?
4. Click on the source computer to access its profile page. Check what happened around the time of the DNS query, searching for unusual activities, such as who was logged in, and which resources were used. If you already enabled Windows Defender ATP integration, click the Windows Defender ATP badge ![Windows Defender ATP badge](./media/wd-badge.png) to further investigate the machine. Using Windows Defender ATP you can see which processes and alerts occurred around the time of the alert.

**Remediation**

If the registered query domain is not trusted after your investigation, we recommend blocking the destination domain to avoid all future communication. 

## Suspicious modification of sensitive groups <a name="suspicious-midification-of-sensitive-groups"></a>

*Previous name:* Suspicious modification of sensitive groups

**Description**

Attackers typically add users to highly privileged groups. They do so to gain access to more resources, and to gain persistency. The detection relies on profiling the group modification activities of users, and alerting when an abnormal addition to a sensitive group is seen. Profiling is continuously performed by Azure ATP. The minimum period before an alert can be triggered is one month per each domain controller.

For a definition of sensitive groups in Azure ATP, see [Working with the sensitive accounts](sensitive-accounts.md).

The detection relies on [events audited on domain controllers](configure-event-collection.md).
To make sure your domain controllers audit the needed events.

**Investigation**

1. Is the group modification legitimate? </br>Legitimate group modifications that rarely occur, and were not learned as “normal”, might cause an alert, which would be considered a benign true positive.

2. If the added object was a user account, check which actions the user account took after being added to the admin group. Go to the user’s page in Azure ATP to get more context. Were there any other suspicious activities associated with the account before or after the addition took place? Download the **Sensitive group modification** report to see what other modifications were made and by whom during the same time period.

**Remediation**

Minimize the number of users who are authorized to modify sensitive groups.

Set up [Privileged Access Management for Active Directory](https://docs.microsoft.com/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services) if applicable.

## Suspicious service creation
<a name="suspicious-service-creation"></a>

*Previous name:* Suspicious service creation

**Description**

A suspicious service has been created on a domain controller in your organization. This alert relies on event 7045 in order to identify this suspicious activity. 

**Investigation**

1. If the computer in question is an administrative workstation, or a computer on which IT team members and service accounts perform administrative tasks, this may be a false positive and you may need to **Suppress** the alert and add it to the Exclusions list if necessary.

2. Is the service something you recognize on this computer?

 - Is the **account** in question allowed to install this service?

 - If the answer to both questions is *yes*, then **Close** the alert or add it to the Exclusions list.

3. If the answer to either questions is *no*, then this should be considered a true positive.

**Remediation**

- Implement less-privileged access on domain machines to allow only specific users the right to create new services.


## Suspicious VPN connection
<a name="suspicious-vpn-detection"></a>

*Previous name:* Suspicious VPN connection 

**Description**

Azure ATP learns the entity behavior for users VPN connections over a sliding period of one month. 

The VPN-behavior model is based on the following activities: the machines the users logged in to and the locations the users connect from. 

An alert is opened when there is a deviation from the user’s behavior based on machine learning algorithm.

**Investigation**

1.	Is the user in question supposed to be performing these operations?
2.	Consider the following cases as potential false positives: a user who changed his location, a user that is traveling and connect from a new device.

**Remediation**

1.	Consider resetting the password of that user. This prevents the attacker from creating new VPN connections using the old credentials.
2.	Consider blocking this user from connecting through VPN.


## Suspected WannaCry ransomware attack <a name="unusual-protocol-implementation"></a>

*Previous name:* Unusual protocol implementation (potential WannaCry ransomware attack)

**Description**

Attackers use tools that implement various protocols in non-standard ways. While this type of network traffic is accepted by Windows without warnings, Azure ATP is able to recognize potential malicious intent. The behavior is indicative of techniques used by advanced ransomware, such as WannaCry.

**Investigation**

Review the unusual activity in the security alert on the activity time line. Click on the security alert to get to its details page, then review the potentially affected entities and the evidence list. 

Is this a *true positive*, *benign true positive*, or *false positive*? 

1. Check if WannaCry is running on the source computer. 

2. If yes, this alert is a true positive. To understand the scope of the breach:
      - Investigate the source computer
      - Investigate the compromised computer. 

2. If the source computer is not running an attack tool, sometimes, applications implement their own NTLM or SMB stack. Check if the source computer is running an application that implements its own NTLM or SMB stack.

      1. If the computer is running its own stack, and it should not be, fix the application configuration. In such a case, it is a benign activity, the security alert can be closed.

      2. If the computer is running its own stack and it the configuration is correct, the security alert can be closed and the computer excluded, as it is  probably a benign activity.

3. Click on the source computer to go to its profile page. Check what happened around the time of the alert, searching for unusual activities, such as who was logged in, and which resources where accessed. 

4. If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge ![wd badge](./media/wd-badge.png) to further investigate the machine. In Windows Defender ATP, you can see which processes and alerts occurred around the time of the alert.


**Remediation**

1. Contain the source computer. 
      - [Remove WannaCry](https://support.microsoft.com/help/890830/remove-specific-prevalent-malware-with-windows-malicious-software-remo)
      - WanaKiwi can decrypt the data in the hands of some ransom software, but only if the user has not restarted or turned off the computer. For more information, see [WannaCry Ransomware](https://answers.microsoft.com/en-us/windows/forum/windows_10-security/wanna-cry-ransomware/5afdb045-8f36-4f55-a992-53398d21ed07?auth=1)
      - Look for users logged on around the time of the activity, as they might also be compromised. Reset their passwords and enable MFA 
2. Patch all of your machines, making sure to apply security updates. 
      - [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

## Suspected use of Metasploit hacking framework


*Previous name:* Unusual protocol implementation (potential use of Metasploit hacking tools)

**Description**

Attackers use tools that implement various protocols (SMB, Kerberos, NTLM) in non-standard ways. While this type of network traffic is accepted by Windows without warnings, Azure ATP is able to recognize potential malicious intent. The behavior is indicative of techniques such as use of the Metasploit hacking framework. 

**Investigation**

Review the unusual activity in the security alert on the activity time line. Click on the security alert to get to its details page, then review the potentially affected entities and the evidence list.

Is this a *true positive*, *benign true positive*, or *false positive*? 

1. Check if the source computer is running an attack tool such as Metasploit or Medusa. 

2. If yes, it is a true positive. To understand the scope of the breach:
      - Investigate the source computer
      - Investigate the compromised computer. 

3. If the source computer is not running an attack tool, sometimes, applications implement their own NTLM or SMB stack. Check if the source computer is running an application that implements its own NTLM or SMB stack.

4. If the computer is running its own NTML or SMB stack, and it should not be, fix the application configuration.
      1. In such a case, it is a benign activity, the security alert can be closed. 
      2. If the computer is running its own stack and it the configuration is correct, the security alert can be closed and the computer excluded, as it is  probably a benign activity.

5. Click on the source computer to go to its profile page. Check what happened around the time of the alert, searching for unusual activities, such as: who was logged in, which resources where accessed. If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge ![wd badge](./media/wd-badge.png) to further investigate the machine. In Windows Defender ATP, you can see which processes and alerts occurred around the time of the alert.


**Remediation**

1. Reset the passwords of the compromised users and enable multi-factor authentication.
2. Contain the source computer
   1. Find the tool that performed the attack and remove it.
   2. Search for users logged on around the time of the activity, as they may also be compromised.
   3. Reset their passwords and enable multi-factor authentication. 
4. Reset the passwords of the source user and enable multi-factor authentication. 
5. [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)


## Suspected overpass-the-hash attack (Kerberos) <a name="unusual-protocol-implementation"></a>

*Previous name:* Unusual Kerberos protocol implementation (potential overpass-the-hash attack) 

**Description**

Attackers use tools that implement various protocols such as Kerberos and SMB in non-standard ways. While this type of network traffic is accepted by Windows without warnings, Azure ATP is able to recognize potential malicious intent. The behavior is indicative of techniques such as Over-Pass-the-Hash and brute force, as well as exploits used by advanced ransomware, for example, WannaCry.

**Investigation**

Review the unusual activity in the security alert on the activity time line. Click on the security alert to get to its details page, then review the potentially affected entities and the evidence list.

Is this a *true positive*, *benign true positive*, or *false positive*? 

 1. Sometimes applications implement their own Kerberos stack, not in accordance with the Kerberos RFC.
   1. Check if the source computer is running its own Kerberos stack. 
   2. If the computer is running its own Kerberos stack, and it should not be, fix the application configuration. In such a case, it is a benign activity, the security alert can be closed. 
   3. If the computer is running its own Kerberos stack and it the configuration is correct, the security alert can be closed and the computer excluded, as it is  probably a benign activity.

 **Remediation**

1. Reset the passwords of the compromised users and enable  multi-factor authentication.
2. Contain the source computer. 
   1. Find the tool that performed the attack and remove it.
   2. Search for users logged on around the time of the activity, as they may also be compromised. 
   3. Reset their passwords and enable multi-factor authentication. 
4. Reset the passwords of the source user and enable multi-factor authentication. 

## Suspected brute force attack (SMB) <a name="unusual-protocol-implementation-smb"></a>

*Previous name:* Unusual protocol implementation (potential use of malicious tools such as Hydra)

**Description**

Attackers use tools that implement various protocols such as SMB, Kerberos, and NTLM in non-standard ways. While this type of network traffic is accepted by Windows without warnings, Azure ATP is able to recognize potential malicious intent. The behavior is indicative of brute force techniques. 

**Investigation**

Review the unusual activity in the security alert on the activity time line. Click on the security alert to get to its details page, then review the potentially affected entities and the evidence list.

Is this a *true positive*, *benign true positive, or *false positive*? 

1. Check if the source computer is running an attack tool such as Hydra. 
   1. If yes, it is a true positive. To understand the scope of the breach:
      - Investigate the source computer
      - Investigate the compromised computer. 

2. If the source computer is not running an attack tool, sometimes, applications implement their own NTLM or SMB stack. Check if the source computer is running an application that implements its own NTLM or SMB stack.

3. Click on the source computer to go to its profile page. Check what happened around the time of the alert, searching for unusual activities, such as who was logged in and which resources where accessed. If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge ![wd badge](./media/wd-badge.png) to further investigate the machine. In Windows Defender ATP, you can see which processes and alerts occurred around the time of the alert.

**Remediation**

1. Reset the passwords of the guessed users and enable  multi-factor authentication.
2. Add the guessed users to a watchlist.
3. Contain the source computer
   1. Find the tool that performed the attack and remove it.
   2. Search for users logged on around the time of the activity, as they may also be compromised.
   3. Reset their passwords and enable multi-factor authentication. 
4. Enforce Complex and long passwords in the organization. Complex and long passwords provide the necessary first level of security against future brute-force attacks.
5. [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

## Suspected brute force attack (Kerberos, NTLM)
<a name="suspicious-authentication-failures"></a>

*Previous name:* Suspicious authentication failures

**Description**
In a brute-force attack, an attacker attempts to authenticate with many different passwords for different accounts until a correct password is found for at least one account. Once found, an attacker can log in using that account.

In this detection, an alert is triggered when many authentication failures using Kerberos or NTLM are detected. This can be either horizontally with a small set of passwords across many users; or vertically with a large set of passwords on just a few users; or any combination of these two options.

**Timeframe**
The minimum period before this specific alert can be triggered is a minimum of one week after sensor deployment.

**Investigation**

1. Click the alert to view: 
   - List of the attacked accounts
   - List of guessed accounts in which login attempts ended with successful authentication
   - If the authentication attempts were performed using NTLM, you will see relevant event activities
   - If the authentication attempts were performed using Kerberos, you will see relevant network activities
2. Click on the source computer to go to its profile page. Check what happened around the time of these attempts, searching for unusual activities, such as who was logged in and which resources where accessed. If you enabled Windows Defender ATP integration, click the Windows Defender ATP badge   to further investigate the machine. Use Windows Defender ATP, to see which processes and alerts occurred around the time of the alert.

3. If the authentication was performed using NTLM, and you see the alert occurs many times without enough information about the server the source machine tried to access, enable NTLM auditing on the involved domain controllers. Enable NTLM auditing on the involved domain controllers by turning on event 8004. This is the NTLM authentication event that includes information about the source computer, user account, and server the source machine tried to access. After you know which server sent the authentication validation, investigate the server by checking events, such as event 4624 to better understand the authentication process.
<br>
1. Click **Download details** to view in an Excel spreadsheet. 

**Remediation**

Complex and long passwords provide the necessary first level of security against brute force attacks.

## User and group membership reconnaissance (SAMR)

*Previous name:* Reconnaissance using directory services queries
<a name="reconnaissance-using-directory-service-queries"></a>

**Description** 
User and group membership reconnaissance are used by attackers to map the directory structure and target privileged accounts for later steps in an attack. The Security Account Manager Remote (SAM-R) protocol is one of the methods used to query the directory to perform this type of mapping.  
In this detection, no alerts are triggered in the first month after Azure ATP is deployed (learning period). During the learning period, Azure ATP profiles which SAM-R queries are made from which computers, both enumeration and individual queries of sensitive accounts. 

**Learning period**
4 weeks per domain controller starting from the first network activity of SAMR against the specific DC. 

Is this alert a **True Positive**, **Benign True Positive** , or **False Positive**? 

1. Click on the source computer to go to its profile page.        - Is the source computer supposed to generate activities of this type?  
      - If yes, you can *Close* the security alert and exclude that computer, it is probably a benign true positive activity. 
2. Check the user/s that performed the operation. 
      - Do they normally log into that source computer or are they administrators that should be performing those specific actions?   
      - Check the user profile, and their related user activities. Understand their normal behavior and search for additional suspicious activities using the user investigation guide. 
      - If yes, *Close* the security alert as a benign activity. 
  
**Understand the scope of the breach**

1. Check which queries were performed (for example, Enterprise admins, or Administrator) and determine if  they were successful.
2. Investigate each exposed user using the user investigation guide.
3. Investigate the source computer.  
  
**Suggested remediation and steps for prevention**

1. Contain the source computer.
2. Find the tool that performed the attack and remove it.
3. Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA.
4. Reset the source user password and enable MFA.
5. Apply Network access: Restrict clients allowed to make remote calls to SAM group policy.

## User and IP address reconnaissance (SMB) <a name="reconnaissance-using-smb-session-enumeration"></a>

*Previous name:* Reconnaissance using SMB Session Enumeration

### Description

Enumeration using Server Message Block (SMB) protocol enables attackers to get information about where users recently logged on. Once attackers have this information, they can move laterally in the network to get to a specific sensitive account.

In this detection, an alert is triggered when an SMB session enumeration is performed against a domain controller, because this should not happen.

 **TP, B-TP or FP**

Security scanners and applications may legitimately query domain controllers for open SMB sessions.

1. Is this source computer supposed to generate activities of this type?
2. Is there some kind of security scanner running on the source computer?  
    If the answer is yes, it is probably a B-TP activity. You can *Close* the security alert and exclude that computer.
3. Check which user(s) performed the operation.
    Are they supposed to perform those actions?  
    If the answer is yes, you can *Close* the security alert as a B-TP activity.

**Understand the scope of the breach**

1. Investigate the source computer.  
2. On the alert page, check which users were exposed, if any. For each exposed user, check their profile for further investigation. It is recommended to start by investigating sensitive and high investigation priority users, first.

**Suggested remediation and prevention steps**

Use the [Net Cease tool](https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b) to harden your environment against this attack.

> [!NOTE]
> To disable a security alert, contact support.


## See Also
- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
