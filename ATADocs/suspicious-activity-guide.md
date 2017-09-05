---
# required metadata

title: ATA suspicious activity guide | Microsoft Docs
d|Description: This article provides a list of the suspicious activities ATA can detect and steps for remediation.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 09/4/2017
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 1fe5fd6f-1b79-4a25-8051-2f94ff6c71c1

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Advanced Threat Analytics version 1.8*


# Advanced Threat Analytics suspicious activity guide

Following proper investigation, any suspicious activity can be classified as:

-   **True positive**: A malicious action detected by ATA.

-   **Benign true positive**: An action detected by ATA that is real but not malicious, such as a penetration test.

-   **False positive**: A false alarm, meaning the activity didn’t happen.

For more information on how to work with ATA alerts, see [ATA Health Center](ata-health-center.md).

For questions or feedback, contact us at [ATAEval@microsoft.com](mailto:ATAEval@microsoft.com).

## Abnormal Sensitive Group Modification


**Description**

Attackers add users to highly privileged groups. They do so to gain access to more resources and to gain persistency. The detection relies on profiling the group modification activities of users, and alerting when an abnormal addition to a sensitive group is seen. Profiling is continuously performed by ATA. The minimum period before an alert can be triggered is one month per each domain controller.

For a definition of sensitive groups in ATA, see [Working with the ATA console](working-with-the-ata-console.md#sensitive-groups).


The detection relies on [events audited on domain controllers](https://docs.microsoft.com/advanced-threat-analytics/configure-event-collection).
Use the tool referenced in [ATA Auditing (AuditPol, Advanced Audit Settings Enforcement, Lightweight Gateway Service discovery)](https://aka.ms/ataauditingblog) to make sure your domain controllers audit the needed events.

**Investigation**

Is the group modification legitimate? 

Legitimate group modifications that rarely occur, and were not learned as “normal”, might cause an alert, which would be considered a benign true positive.

In case the added object was a user account, check which actions the user account took after being added to the admin group. Go to the user’s page in ATA to get more context. Were there any other suspicious activities associated with the account before or after the addition took place? Download the **Sensitive group modification** report to see what other modifications were made and by whom during the same time period.

**Remediation**

Minimize the number of users who are authorized to modify sensitive groups.

Set up [Privileged Access Management for Active Directory](https://docs.microsoft.com/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services) if applicable.

## Broken trust between computers and domain

**Description**

Broken trust means that Active Directory security requirements may not be in effect for the computers in question. This is often considered a baseline security and compliance failure and a soft target for attackers. In this detection, an alert is triggered if more than 5 Kerberos authentication failures are seen from a computer account in 24 hours.

**Investigation**

Is the computer in question allowing domain users to log on? 
- If yes, you may ignore this computer in the remediation steps.

**Remediation**

Rejoin the machine back to the domain if necessary or reset the machine's password.

## Brute force attack using LDAP simple bind

**Description**

>[!NOTE]
> The main difference between **Suspicious authentication failures** and this detection is that in this detection, ATA can determine whether different passwords were in use.

In a brute-force attack, an attacker attempts to authenticate with many different passwords for different accounts until a correct password is found for at least one account. Once found, an attacker can log in using that account.

In this detection, an alert is triggered when ATA detects many different passwords being used. This can be either *horizontally* with a small set of passwords across many users; or *vertically”* with a large set of passwords on just a few users; or any combination of these two options.

**Investigation**

If there are many accounts involved, click **Download details** to view the list in an Excel spreadsheet.

Click on the alert to go to its dedicated page. Check if any login attempts ended with a successful authentication. The attempts would appear as **Guessed accounts** on the right side of the infographic. If yes, are any of the **Guessed accounts** normally used from the source computer? If yes, **Suppress" the suspicious activity.

If there are no **Guessed accounts**, are any of the **Attacked accounts** normally used from the source computer? If yes,**Suppress" the suspicious activity.

**Remediation**

[Complex and long passwords](https://docs.microsoft.com/windows/device-security/security-policy-settings/password-policy) provide the necessary first level of security against brute-force attacks.

## Encryption downgrade activity

**Description**

Various attack methods utilize weak Kerberos encryption cyphers. In this detection, ATA learns the Kerberos encryption types used by computers and users, and alerts you when a weaker cypher is used that: (1) is unusual for the source computer and/or user; and (2) matches known attack techniques.

There are three detection types:

1.  Skeleton Key – is malware that runs on domain controllers and allows authentication to the domain with any account without knowing its password. This malware often uses weaker encryption algorithms to encipher the user's passwords on the domain  controller. In this detection, the encryption method of the KRB_ERR message from the source computer was downgraded compared to the previously learned behavior.

2.  Golden Ticket – In a [Golden Ticket](#golden-ticket) alert, the encryption method of the TGT field of TGS_REQ (service request) message from the source computer was downgraded compared to the previously learned behavior. Note that this is not based on a time anomaly (as in the other Golden Ticket detection). In addition, there was no Kerberos authentication request associated with the above service request detected by ATA.

3.  Overpass-the-Hash – The AS_REQ message encryption type from the source computer was downgraded compared to the previously learned behavior (that is, the computer was using AES).

**Investigation**

First check the description of the alert, to see which of the above three detection types you’re dealing with.

1.  Skeleton Key – You can check if Skeleton Key has affected your domain controllers by using [the scanner written by the ATA team](https://gallery.technet.microsoft.com/Aorato-Skeleton-Key-24e46b73).
    If the scanner finds malware on 1 or more of your domain controllers, it is a true positive.

2.  Golden Ticket – there are cases in which a custom application that is rarely used, is authenticating using a lower encryption cipher. Check if there are any such custom apps on the source computer. If so, it is probably a benign true positive and can be suppressed.

3.  Overpass-the-Hash – there are cases in which this alert might be triggered when users configured with smart cards are required for interactive login, and this setting is disabled and then enabled. Check if there were changes like this for the account(s) involved. If so, this is probably a benign true positive and can be suppressed.

**Remediation**

1.  Skeleton Key – Remove the malware. For more information, see [Skeleton Key Malware Analysis](https://www.secureworks.com/research/skeleton-key-malware-analysis)
    by SecureWorks.

2.  Golden Ticket – Follow the instructions of the [Golden Ticket](#golden-ticket) suspicious activities.   
    Also, because creating a Golden Ticket requires domain admin rights, implement [Pass the hash recommendations](http://aka.ms/PtH).

3.  Overpass-the-Hash – If the involved account is not sensitive, then reset the password of that account. This will prevent the attacker from creating new Kerberos tickets from the password hash, although the existing tickets can still be used until they expire. If it’s a sensitive account, you should consider resetting the KRBTGT account twice as in the Golden Ticket suspicious activity. Resetting the KRBTGT twice will invalidate all Kerberos tickets in this domain so plan before doing so. See guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/). Also see using the [Reset the KRBTGT account password/keys
    tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). Since this is a lateral movement technique, follow the best practices of [Pass the hash recommendations](http://aka.ms/PtH).

## Golden Ticket<a name="golden-ticket"></a>

**Description**

Attackers with domain admin rights can compromise the [KRBTGT account](https://technet.microsoft.com/library/dn745899(v=ws.11).aspx#Sec_KRBTGT). Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve persistency in the network.

In this detection, an alert will be triggered when a Kerberos ticket granting ticket is used for more than the allowed time permitted as specified in the [Maximum lifetime for user ticket](https://technet.microsoft.com/library/jj852169(v=ws.11).aspx)
security policy.

**Investigation**

Was there any recent (within the last few hours) change made to the **Maximum lifetime for user ticket** setting in group policy? If yes, then **Close** the alert (it was a false positive).

Is the ATA Gateway involved in this alert a virtual machine? If yes, did it recently resume from a saved state? If yes, then **Close** this alert.

If the answer to the above questions is no, assume this is malicious.

**Remediation**

Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys
tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). Resetting the KRBTGT twice will invalidate all Kerberos tickets in this domain so plan before doing so.  
Also, because creating a Golden Ticket requires domain admin rights, implement [Pass the hash recommendations](http://aka.ms/PtH).

## Honeytoken activity


**Description**

Honeytoken accounts are decoy accounts set up to identify and track malicious activity that involves these accounts. Honeytoken accounts should be left unused, while having an attractive name to lure attackers (for example,
SQL-Admin). Any activity from them might indicate malicious behavior.

For more information on honeytoken accounts, see [Install ATA - Step 7.

**Investigation**

1.  Check whether the owner of the source computer used the Honeytoken account to authenticate, using the method described in the suspicious activity page (for example, Kerberos, LDAP, NTLM).

2.  Browse to the source computer(s) profile page(s) and check which other accounts authenticated from them. Check with the owners of those accounts if they used the Honeytoken account.

3.  This could be a non-interactive login, so make sure to check for applications or scripts that are running on the source computer.

If after performing steps 1 through 3, if there’s no evidence of benign use, assume this is malicious.

**Remediation**

Make sure Honeytoken accounts are used only for their intended purpose, otherwise they might generate many alerts.

## Identity theft using Pass-the-Hash attack

**Description**

Pass-the-Hash is a lateral movement technique in which attackers steal a user’s NTLM hash from one computer and use it to gain access to another computer. 

**Investigation**

Was the hash used from a computer that the targeted user owns or regularly uses? If yes, this is a false positive. If not, it is probably a true positive.

**Remediation**

If the involved account is not sensitive, then reset the password of that account. This will prevent the attacker from creating new Kerberos tickets from the password hash, although the existing tickets can still be used until they
expire. If it’s a sensitive account, you should consider resetting the KRBTGT account twice as in the Golden Ticket suspicious activity. Resetting the KRBTGT twice will invalidate all Kerberos tickets in this domain so plan before doing so. See
the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), also see using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). Since this is a lateral movement technique, follow the best practices of [Pass the hash recommendations](http://aka.ms/PtH).

## Identity theft using Pass-the-Ticket attack

**Description**

Pass-the-Ticket is a lateral movement technique in which attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by reusing the stolen ticket. In this detection, a Kerberos ticket is seen used on two (or more) different computers.

**Investigation**

Click the **Download details** button to view the full list of IP addresses involved. Does the IP address of one or both computers belong to a subnet that is allocated from an undersized DHCP pool, for example, VPN or WiFi? Is the IP address shared? For example, by a NAT device? If the answer to any of these questions is yes, then it is a false positive.

Is there a custom application that forwards tickets on behalf of users? If so, it is a benign true positive.

**Remediation**

If the involved account is not sensitive, then reset the password of that account. This will prevent the attacker from creating new Kerberos tickets from the password hash, although the existing tickets can still be used until they expire.  
If it’s a sensitive account, you should consider resetting the KRBTGT account twice as in the Golden Ticket suspicious activity. Resetting the KRBTGT twice will invalidate all Kerberos tickets in this domain so plan before doing so. See the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), also see using the [Reset the KRBTGT account password/keys
tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51).  Since this is a lateral movement technique, follow the best practices in [Pass the hash recommendations](http://aka.ms/PtH).

## Malicious Data Protection Private Information Request

**Description**

The Data Protection API (DPAPI) is used by Windows to securely protect passwords saved by browsers, encrypted files, and other sensitive data. Domain controllers hold a backup master key that can be used to decrypt all secrets encrypted with
DPAPI on domain-joined Windows machines. Attackers can use that master key to decrypt any secrets protected by DPAPI on all domain-joined machines.
In this detection, an alert will be triggered when the DPAPI is used to retrieve the backup master key.

**Investigation**

Is the source computer running an organization-approved advanced security scanner against Active Directory?

If yes and it should always be doing so, **Close and exclude** the suspicious activity.

If yes and it should not do this, **Close** the suspicious activity.

**Remediation**

To use DPAPI, an attacker needs domain admin rights. Implement [Pass the hash recommendations](http://aka.ms/PtH).

## Malicious replication requests


**Description**

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with all other domain controllers. Given necessary permissions, attackers can initiate a replication request, allowing them to retrieve the data stored in Active Directory, including password hashes.

In this detection, an alert will be triggered when a replication request is initiated from a computer that is not a domain controller.

**Investigation**

Is the computer in question a domain controller? For example, a newly promoted domain controller that had replication issues. If yes, **Close and exclude** the suspicious activity.  
Is the computer in question supposed to be replicating data from Active Directory? For example, Azure AD Connect. If yes, **Close and exclude** the suspicious activity.

**Remediation**

Validate the following permissions: 
- Replicate directory changes   
- Replicate directory changes all  

For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx).
You can leverage [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a Windows PowerShell script to determine who in the domain has these permissions.

## Massive object deletion

**Description**

In some scenarios, attackers perform a denial of service (DoS) rather than just stealing information. Deleting a large number of accounts is one DoS technique.

In this detection, an alert will be triggered when more than 5% of all accounts are deleted. The detection requires read access to the deleted object container.  
For information about configuring read-only permissions on the deleted object container, see **Changing permissions on a deleted object container** in [View or Set Permissions on a Directory Object](https://technet.microsoft.com/library/cc816824%28v=ws.10%29.aspx).

**Investigation**

Review the list of deleted accounts and understand if there is a pattern or a business reason that might justify this massive deletion.

**Remediation**

Remove permissions for users who can delete accounts in Active Directory. For more information, see [View or Set Permissions on a Directory Object](https://technet.microsoft.com/library/cc816824%28v=ws.10%29.aspx).

## Privilege escalation using forged authorization data

**Description**

Known vulnerabilities in older versions of Windows Server allow attackers to manipulate the Privileged Attribute Certificate (PAC), a field in the Kerberos ticket that contains a user authorization data (in Active Directory this is group membership), granting attackers additional privileges.

**Investigation**

Click on the alert to get to its details page.

Is the destination computer (under the **ACCESSED** column) patched with MS14-068 (domain controller) or MS11-013 (server)? If yes, **Close** the suspicious activity (it is a false positive).

If not, does the source computer (under the **FROM** column) an OS/application known to modify the PAC? If yes, **Suppress** the suspicious activity (it is a benign true positive).

If the answer was no to the above two questions, assume this is malicious.

**Remediation**

Make sure all domain controllers with operating systems up to Windows Server 2012 R2 are installed with [KB3011780](https://support.microsoft.com/help/2496930/ms11-013-vulnerabilities-in-kerberos-could-allow-elevation-of-privilege) and
all member servers and domain controllers up to 2012 R2 are up-to-date with KB2496930. For more information, see [Silver PAC](https://technet.microsoft.com/library/security/ms11-013.aspx) and [Forged PAC](https://technet.microsoft.com/library/security/ms14-068.aspx).

## Reconnaissance using directory services queries

**Description**

Directory services reconnaissance is used by attackers to map the directory structure and target privileged accounts for later steps in an attack. The Security Account Manager Remote (SAM-R) protocol is one of the methods used to query the directory to perform such mapping.

In this detection, no alerts would be triggered in the first month after ATA is deployed. During the learning period, ATA profiles which SAM-R queries are made from which computers, both enumeration and individual queries of sensitive accounts.

**Investigation**

Click on the alert to get to its details page. Check which queries were performed (for example, Enterprise admins, or Administrator) and whether or not they were successful.

Are such queries supposed to be made from the source computer in question?

If yes and the alert gets updated, **Suppress** the suspicious activity.

If yes and it should not do this anymore, **Close** the suspicious activity.

If there’s information on the involved account: are such queries supposed to be made by that account or does that account normally log in to the source computer?

If yes and the alert gets updated, **Suppress** the suspicious activity.

If yes and it should not do this anymore, **Close** the suspicious activity.

If the answer was no to all of the above, assume this is malicious.

**Remediation**

Use the [SAMRi10 tool](https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b) to harden your environment against this technique.

## Reconnaissance using DNS

**Description**

Your DNS server contains a map of all the computers, IP addresses, and services in your network. This information is used by attackers to map your network structure and target interesting computers for later steps in their attack.

There are several query types in the DNS protocol. ATA detects the AXFR (Transfer) request originating from non-DNS servers.

**Investigation**

Is the source machine (**Originating from…**) a DNS server? If yes, then this is probably a false positive. To validate, click on the alert to get to its details page. In the table, under **Query**, check which domains were queried. Are these existing domains? If yes, then **Close** the suspicious activity (it is a false positive). In addition, make sure UDP port 53 is open between ATA Gateways and the source computer to prevent future false positives.

Is the source machine running a security scanner? If yes, **Exclude the entities** in ATA, either directly with **Close and exclude** or via the **Exclusion** page (under **Configuration** – available for ATA admins).

If the answer to all the above is no, assume this is malicious.

**Remediation**

Securing an internal DNS server to prevent reconnaissance using DNS from occurring can be accomplished by disabling or restricting zone transfers only to specified IP addresses. For more information on restricting zone transfers, see [Restrict Zone Transfers](https://technet.microsoft.com/library/ee649273(v=ws.10).aspx).
Modifying zone transfers is one task among a checklist that should be addressed for [securing your DNS servers from both internal and external attacks](https://technet.microsoft.com/library/cc770432(v=ws.11).aspx).

## Reconnaissance using SMB Session Enumeration


**Description**

Server Message Block (SMB) enumeration enables attackers to get information about where users recently logged on. Once attackers have this information, they can move laterally in the network to get to a specific sensitive account.

In this detection, an alert will be triggered when an SMB session enumeration is performed against a domain controller, because this should not happen.

**Investigation**

Click on the alert to get to its details page. Check which account/s performed the operation and which accounts were exposed, if any.

Is there some kind of security scanner running on the source computer? If yes, **Close and exclude** the suspicious activity.

Check which involved user/s performed the operation. Do they normally log into the source computer or are they administrators who should perform such actions?  

If yes and the alert gets updated, **Suppress** the suspicious activity.  

If yes and it should not do this anymore, **Close** the suspicious activity.

If the answer to all the above is no, assume this is malicious.

**Remediation**

Use the [Net Cease tool](https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b) to harden your environment against this attack.

## Remote execution attempt detected

**Description**

Attackers who compromise administrative credentials or use a zero-day exploit can execute remote commands on your domain controller. This can be used for gaining persistency, collecting information, denial of service (DOS) attacks or any other reason. ATA detects PSexec and Remote WMI connections.

**Investigation**

This is common for administrative workstations and IT team members and service accounts that perform administrative tasks against the domain controllers. If this is this the case, and the alert gets updated since the same admin and/or computer are performing the task, then Suppress the alert.

Is the **computer** in question allowed to perform this remote execution against your domain controller?

Is the **account** in question allowed to perform this remote execution against your domain controller?

If the answer to both questions is *yes*, then **Close** the alert.

If the answer to either questions is *no*, then this should be considered a true positive.

**Remediation**

Restrict remote access to domain controllers from non-Tier 0 machines.

Implement [privileged access](https://technet.microsoft.com/windows-server-docs/security/securing-privileged-access/securing-privileged-access) to allow only hardened machines to connect to domain controllers for admins.

## Sensitive account credentials exposed & Services exposing account credentials

**Description**

Some services send account credentials in plain text. This can even happen for sensitive accounts. Attackers monitoring network traffic can catch and then reuse these credentials for malicious purposes. Any clear text password for a sensitive account will trigger the alert, while for non-sensitive accounts the alert is triggered if five or more different accounts  send clear text passwords from the same source computer. 

**Investigation**

Click on the alert to get to its details page. See which accounts were exposed. If there are many such accounts, click **Download details** to view the list in an Excel spreadsheet.

Usually there’s a script or legacy application on the source computers that uses LDAP simple bind.

**Remediation**

Verify the configuration on the source computers and make sure not to use LDAP simple bind. Instead of using LDAP simple binds you can use LDAP SALS or LDAPS.

## Suspicious authentication failures

**Description**

In a brute-force attack, an attacker attempts to authenticate with many different passwords for different accounts until a correct password is found for at least one account. Once found, an attacker can log in using that account.

In this detection, an alert will be triggered when many authentication failures occurred, this can be either horizontally with a small set of passwords across many users; or vertically with a large set of passwords on just a few users; or any combination of these two options.

**Investigation**

If there are many accounts involved, click **Download details** to view the list in an Excel spreadsheet.

Click on the alert to go to its details page. Check if any login attempts ended with a successful authentication, these would appear as **Guessed accounts** on the right side of the infographic. If yes, are any of the **Guessed accounts** normally used from the source computer? If yes, **Suppress** the suspicious activity.

If there are no **Guessed accounts**, are any of the **Attacked accounts** normally used from the source computer? If yes, **Suppress** the suspicious activity.

**Remediation**

[Complex and long passwords](https://docs.microsoft.com/windows/device-security/security-policy-settings/password-policy) provide the necessary first level of security against brute-force attacks.

## Suspicion of identity theft based on abnormal behavior

**Description**

ATA learns the entity behavior for users, computers, and resources over a sliding three week period. The behavior model is based on the following activities: the machines the entities logged in to, the resources the entity requested access to, and the time these operations took place. ATA sends an alert when there is a deviation from the entity’s behavior based on machine learning algorithms. 

**Investigation**

Is the user in question supposed to be performing these operations?

Consider the following cases as potential false positives: a user who returned from vacation, IT personnel who perform excess access as part of their duty (for example a spike in help-desk support in a given day or week), remote desktop applications.+ 
If you **Close and exclude** the alert, the user will no longer be part of the detection


**Remediation**

Depending on what caused this abnormal behavior to occur, different actions should be taken. For example, if this is due to scanning of the network, the machine from which this occurred should be blocked from the network (unless it is approved).

## Unusual protocol implementation


**Description**

Attackers use tools that implement various protocols (SMB, Kerberos, NTLM) in non-standard ways. While this type of network traffic is generally accepted by Windows without warnings, ATA is able to recognize potential malicious intent. The behavior is indicative of techniques such as Over-Pass-the-Hash and brute force, as well as exploits used by advanced ransomware, for example, WannaCry.

**Investigation**

First, identify the protocol that is unusual – from the Suspicious activity time line,  click on the suspicious activity to get to its details page; the protocol appears above the arrow: Kerberos or NTLM.

- **Kerberos**: This will often be triggered if a hacking tool such as Mimikatz has been used, potentially performing an Overpass-the-Hash attack. Check if the source computer is running an application that implements its own Kerberos stack, not in accordance with the Kerberos RFC. If that is the case, it is a benign true positive and you can **Close** the alert. If the alert keeps being triggered, and it is still the case, you can **Suppress** the alert.

- **NTLM**: Could be either WannaCry or tools such as Metasploit, Medusa, and Hydra.  

To determine whether this is a WannaCry attack, perform the following steps:

1. Check if the source computer is running an attack tool such as Metasploit, Medusa, or Hydra.

2. If no attack tools are found, check if the source computer is running an application that implements its own NTLM or SMB stack.

3. If not then check if this is caused by WannaCry by running a WannaCry scanner script, for example [this scanner](https://github.com/apkjet/TrustlookWannaCryToolkit/tree/master/scanner) against the source computer involved in the suspicious activity. If the scanner finds that the machine as infected or vulnerable, work on patching the machine and removing the malware and blocking it from the network.

4. If the script didn't find that the machine is infected or vulnerable, then it could still be infected but SMBv1 might have been disabled or the machine has been patched, which would affect the scanning tool.

**Remediation**

Patch all your machines, especially applying security updates.

1. [Disable SMBv1](https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/)

2. [Remove WannaCry](https://support.microsoft.com/help/890830/remove-specific-prevalent-malware-with-windows-malicious-software-remo)

3. WanaKiwi can decrypt the data in the hands of some ransom software, but only if the user has not restarted or turned off the computer. For more information, see [Wanna Cry Ransomware](https://answers.microsoft.com/en-us/windows/forum/windows_10-security/wanna-cry-ransomware/5afdb045-8f36-4f55-a992-53398d21ed07?auth=1)

## Related Videos
- [Joining the security community](https://channel9.msdn.com/Shows/Microsoft-Security/Join-the-Security-Community)


## See Also
- [ATA suspicious activity playbook](http://aka.ms/ataplaybook)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Investigating Forged PAC attacks](use-case-forged-pac.md)
- [Troubleshooting ATA known errors](troubleshooting-ata-known-errors.md)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
