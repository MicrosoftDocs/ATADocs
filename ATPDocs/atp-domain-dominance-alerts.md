---
# required metadata

title: Azure ATP domain dominance security alerts | Microsoft Docs
d|Description: This article explains the Azure ATP alerts issued when attacks typically part of domain dominance phase efforts are detected against your organization.
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 08/26/2019
ms.topic: tutorial
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 0b3a1db5-0d43-49af-b356-7094cc85f0a5

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Tutorial: Domain dominance alerts  

Typically, cyber attacks are launched against any accessible entity, such as a low-privileged user, and then quickly move laterally until the attacker gains access to valuable assets. Valuable assets can be sensitive accounts, domain administrators, or highly sensitive data. Azure ATP identifies these advanced threats at the source throughout the entire attack kill chain and classifies them into the following phases:

1. [Reconnaissance](atp-reconnaissance-alerts.md)
2. [Compromised credentials](atp-compromised-credentials-alerts.md)
3. [Lateral Movements](atp-lateral-movement-alerts.md)
4. **Domain dominance**
5. [Exfiltration](atp-exfiltration-alerts.md)

To learn more about how to understand the structure, and common components of all Azure ATP security alerts, see [Understanding security alerts](understanding-security-alerts.md).

The following security alerts help you identify and remediate **Domain dominance** phase suspicious activities detected by Azure ATP in your network. In this tutorial, learn how to understand, classify, prevent, and remediate the following attacks:

> [!div class="checklist"]
> * Malicious request of Data Protection API master key (external ID 2020)
> * Remote code execution attempt (external ID 2019)
> * Suspected DCShadow attack (domain controller promotion) (external ID 2028)
> * Suspected DCShadow attack (domain controller replication request) (external ID 2029)
> * Suspected DCSync attack (replication of directory services) (external ID 2006)
> * Suspected Golden Ticket usage (encryption downgrade) (external ID 2009)
> * Suspected Golden Ticket usage (forged authorization data) (external ID 2013)
> * Suspected Golden Ticket usage (nonexistent account) (external ID 2027)
> * Suspected Golden Ticket usage (ticket anomaly) (external ID 2032)
> * Suspected Golden Ticket usage (time anomaly) (external ID 2022)
> * Suspected Skeleton Key attack (encryption downgrade) (external ID 2010)
> * Suspicious additions to sensitive groups (external ID 2024)
> * Suspicious service creation (external ID 2026)

## Malicious request of Data Protection API master key (external ID 2020) 

*Previous name:* Malicious Data Protection Private Information Request

**Description**

The Data Protection API (DPAPI) is used by Windows to securely protect passwords saved by browsers, encrypted files, and other sensitive data. Domain controllers hold a backup master key that can be used to decrypt all secrets encrypted with DPAPI on domain-joined Windows machines. Attackers can use the master key to decrypt any secrets protected by DPAPI on all domain-joined machines.
In this detection, an Azure ATP alert is triggered when the DPAPI is used to retrieve the backup master key.

**TP, B-TP, or FP?**

Advanced security scanners may legitimately generate this type of activity against Active Directory.

1. Check if the source computer is running an organization-approved advanced security scanner against Active Directory?

    - If the answer is **yes**, and it should not be running, fix the application configuration. This alert is a **B-TP** and can be **Closed**.
    - If the answer is **yes**, and it should always do this, **Close** the alert, and exclude that computer, it is probably a **B-TP** activity.

**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md).
2. If a [source user](investigate-a-user.md) exists, investigate.

**Suggested remediation and steps for prevention**

1. Reset the password of the source user and enable MFA.
2. Contain the source computer. 
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.
3. The stolen private key is never changed. Meaning the actor can always use the stolen key to decrypt protected data in the target domain. A methodological way to change this private key does not exist. 
    - To create a key, use the current private key, create a key, and re-encrypt every domain master key with the new private key.

## Remote code execution attempt (external ID 2019) 

*Previous name:* Remote code execution attempt

**Description**

Attackers who compromise administrative credentials or use a zero-day exploit can execute remote commands on your domain controller. This can be used for gaining persistency, collecting information, denial of service (DOS) attacks or any other reason. Azure ATP detects PSexec, Remote WMI, and PowerShell connections.

**TP, B-TP, or FP**

Administrative workstations, IT team members, and service accounts can all perform legitimate administrative tasks against domain controllers.

1. Check if the source computer or user is supposed to run those types of commands on your domain controller?  
    - If the source computer or user is supposed to run those types of commands, **Close** the security alert as a **B-TP** activity.  
    - If the source computer or user is supposed to run those commands on your domain controller, and will continue to do so, it is a **B-TP** activity. **Close** the security alert and exclude the computer.


**Understand the scope of the breach**

1. Investigate the [source computer](investigate-a-computer.md) and [user](investigate-a-user.md).
2. Investigate the [domain controller](investigate-a-computer.md).

**Suggested remediation and steps for prevention:**

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
3. Implement less-privileged access on domain machines to allow specific users the right to create services. 

> [!NOTE]
> Remote code execution attempt alerts on attempted use of Powershell commands are only supported by ATP sensors.

## Suspected DCShadow attack (domain controller promotion) (external ID 2028) 

*Previous name:* Suspicious domain controller promotion (potential DCShadow attack)

**Description**

A domain controller shadow (DCShadow) attack is an attack designed to change directory objects using malicious replication. This attack can be performed from any machine by creating a rogue domain controller using a replication process.

In a DCShadow attack, RPC, and LDAP are used to:

1. Register the machine account as a domain controller (using domain admin rights).
2. Perform replication (using the granted replication rights) over DRSUAPI and send changes to directory objects.

In this Azure ATP detection, a security alert is triggered when a machine in the network tries to register as a rogue domain controller.

**TP, B-TP, or FP**

If the source computer is a domain controller, failed or low certainty resolution can prevent Azure ATP from being able to confirm identification.  

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
2. Look at the Event Viewer to see [Active Directory events that it records in the directory services log](https://docs.microsoft.com/previous-versions/windows/it-pro/windows-2000-server/cc961809(v=technet.10)/). You can use the log to monitor changes in Active Directory. By default, Active Directory only records critical error events, but if this alert recurs, enable this audit on the relevant domain controller for further investigation.

**Suggested remediation and steps for prevention:**

**Remediation:**

1. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. <br>Reset their passwords and enable MFA.

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
2. Replicate directory changes all.
3. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx). You can use [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a Windows PowerShell script to determine who has these permissions in the domain.

> [!NOTE]
> Suspicious domain controller promotion (potential DCShadow attack) alerts are supported by ATP sensors only.

## Suspected DCShadow attack (domain controller replication request) (external ID 2029) 

*Previous name:* Suspicious replication request (potential DCShadow attack)

**Description**

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with other domain controllers. Given necessary permissions, attackers can grant rights for their machine account, allowing them to impersonate a domain controller. Attackers strive to initiate a malicious replication request, allowing them to change Active Directory objects on a genuine domain controller, which can give the attackers persistence in the domain.
In this detection, an alert is triggered when a suspicious replication request is generated against a genuine domain controller protected by Azure ATP. The behavior is indicative of techniques used in domain controller shadow attacks.

**TP, B-TP, or FP** 

If the source computer is a domain controller, failed or low certainty resolution can prevent Azure ATP from identification. 

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
    <br>Reset their passwords and enable MFA.
2. Remediate the data that was replicated on the domain controllers.

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
2. Replicate directory changes all.
3. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx). You can use [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a Windows PowerShell script to determine who in the domain has these permissions.

> [!NOTE]
> Suspicious replication request (potential DCShadow attack) alerts are supported by ATP sensors only. 

## Suspected DCSync attack (replication of directory services) (external ID 2006) 

*Previous name:* Malicious replication of directory services

**Description**

Active Directory replication is the process by which changes that are made on one domain controller are synchronized with all other domain controllers. Given necessary permissions, attackers can initiate a replication request, allowing them to retrieve the data stored in Active Directory, including password hashes.

In this detection, an alert is triggered when a replication request is initiated from a computer that is not a domain controller.

> [!NOTE]
> If you have domain controllers on which Azure ATP sensors are not installed, those domain controllers are not covered by Azure ATP. When deploying a new domain controller on an unregistered or unprotected domain controller, it may not immediately be identified by Azure ATP as a domain controller. It is highly recommended to install the Azure ATP sensor on every domain controller to get full coverage.

**TP, B-TP, or FP**

If the source computer is a domain controller, failed or low certainty resolution can prevent Azure ATP from identification.   

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

1. Reset the password of the source users and enable MFA.
2. Contain the source computer.
    - Find the tool that performed the attack and remove it.
    - Look for users who were logged on around the same time as the activity occurred, as these users may also be compromised. Reset their passwords and enable MFA.

**Prevention:**

Validate the following permissions:

1. Replicate directory changes.
2. Replicate directory changes all.
3. For more information, see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx). You can use [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a Windows PowerShell script to determine who in the domain has these permissions.

## Suspected Golden Ticket usage (encryption downgrade) (external ID 2009) 

*Previous name:* Encryption downgrade activity

**Description**
Encryption downgrade is a method of weakening Kerberos by downgrading the encryption level of different protocol fields that normally have the highest level of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, Azure ATP learns the Kerberos encryption types used by computers and users, and alerts you when a weaker cypher is used that is unusual for the source computer and/or user and matches known attack techniques.  

In a Golden Ticket alert, the encryption method of the TGT field of TGS_REQ (service request) message from the source computer was detected as downgraded compared to the previously learned behavior. This is not based on a time anomaly (as in the other Golden Ticket detection). In addition, in the case of this alert, there was no Kerberos authentication request associated with the previous service request, detected by Azure ATP.
 
**TP, B-TP, or FP**
<br>Some legitimate resources don’t support strong encryption ciphers and may trigger this alert. 


1. Do all of the source users share something in common? 
   1. For example, are all of your marketing personnel accessing a specific resource that could cause the alert to be triggered?
   2. Check the resources accessed by those tickets. 
       - Check this in Active Directory by checking the attribute *msDS-SupportedEncryptionTypes*, of the resource service account.
   3. If there is only one resource being accessed, check if is a valid resource these users are supposed to access.  

      If the answer to one of the previous questions is **yes**, it is likely to be a **T-BP** activity. Check if the resource can support a strong encryption cipher,  implement a stronger encryption cipher where possible, and **Close** the security alert.

Applications might authenticate using a lower encryption cipher. Some are authenticating on behalf of users, such as IIS and SQL servers. 

1. Check if the source users have something in common.         
   - For example, do all of your sales personnel use a specific app that might trigger the alert?
   - Check if there are applications of this type on the source computer. 
   - Check the computer roles. <br>Are they servers that work with these types of applications? 

     If the answer to one of the previous questions is **yes**, it is likely to be a **T-BP** activity. Check if the resource can support a strong encryption cipher,implement a stronger encryption cipher where possible, and **Close** the security alert.


**Understand the scope of the breach**

1. Investigate the [source computer and resources](investigate-a-computer.md) that were accessed.  
2. Investigate the [users](investigate-a-computer.md). 

**Suggested remediation and steps for prevention** 

**Remediation**
1. Reset the password of the source user and enable MFA. 
2. Contain the source computer. 
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the time of the activity, as they may also be compromised. Reset their passwords and enable MFA.
    - If you have Windows Defender ATP installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.
2. Contain the resources that were accessed by this ticket. 
3. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). 
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and they will not work again until they are renewed or in some cases, the service is restarted. 
    - **Plan carefully before performing the KRBTGT double reset. The KRBTGT double reset impacts all computers, servers, and users in the environment.**

4. Make sure all domain controllers with operating systems up to Windows Server 2012 R2 are installed with [KB3011780](https://www.microsoft.com/download/details.aspx?id=44978) and all member servers and domain controllers up to 2012 R2 are up-to-date with [KB2496930](https://support.microsoft.com/help/2496930/ms11-013-vulnerabilities-in-kerberos-could-allow-elevation-of-privileg). For more information, see [Silver PAC](https://technet.microsoft.com/library/security/ms11-013.aspx) and [Forged PAC](https://technet.microsoft.com/library/security/ms14-068.aspx).

## Suspected Golden Ticket usage (forged authorization data) (external ID 2013)

Previous name: Privilege escalation using forged authorization data

**Description**
Known vulnerabilities in older versions of Windows Server allow attackers to manipulate the Privileged Attribute Certificate (PAC), a field in the Kerberos ticket that contains a user authorization data (in Active Directory this is group membership), granting attackers additional privileges. 
 
**TP, B-TP, or FP**
<br>For computers that are patched with MS14-068 (domain controller) or MS11-013 (server) attempted attacks will not succeed, and will generate Kerberos error. 

1. Check which resources were accessed in the security alert evidence list, and if the attempts were successful or failed.  
2. Check if the accessed computers were patched, as described above? 
    - If the computers were patched, **Close** the security alert as a **B-TP** activity. 

Some Operating Systems or applications are known to modify the authorization data. For example, Linux and Unix services have their own authorization mechanism which may trigger the alert. 

1. Is the source computer running an OS or application that has its own authorization mechanism?  
    - If the source computer is running this type of authorization mechanism, consider upgrading the OS or fixing the application configuration. **Close** the alert as a **B-TP** activity. 
  
**Understand the scope of the breach**
1. Investigate the [source computer](investigate-a-computer.md). 
2. If there is a [source user](investigate-a-user.md), investigate. 
3. Check which resources were accessed successfully and [investigate](investigate-a-computer.md).   
 
**Suggested remediation and steps for prevention** 
1. Reset the password of the source user and enable MFA. 
2. Contain the source computer 
    - Find the tool that preformed the attack and remove it. 
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA. 
3. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). 
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and they will not work again until they are renewed or in some cases, the service is restarted. Plan carefully before performing the KRBTGT double reset, because it impacts all computers, servers and users in the environment.
4. Make sure all domain controllers with operating systems up to Windows Server 2012 R2 are installed with [KB3011780](https://www.microsoft.com/download/details.aspx?id=44978) and all member servers and domain controllers up to 2012 R2 are up-to-date with [KB2496930](https://support.microsoft.com/help/2496930/ms11-013-vulnerabilities-in-kerberos-could-allow-elevation-of-privileg). For more information, see [Silver PAC](https://technet.microsoft.com/library/security/ms11-013.aspx) and [Forged PAC](https://technet.microsoft.com/library/security/ms14-068.aspx).

## Suspected Golden Ticket usage (nonexistent account) (external ID 2027) 

Previous name: Kerberos golden ticket

**Description**
 
Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence. In this detection, an alert is triggered by a nonexistent account. 
 
**TP, B-TP, or FP**
<br>Changes in Active Directory can take time to synchronize.
1. Is the user a known and valid domain user?  
2. Has the user been recently added?  
3. Was the user been recently deleted from Active Directory?  

If the answer is **yes**, to any of the previous questions, **Close** the alert, as a **B-TP** activity.
 
**Understand the scope of the breach**
1. Investigate the [source computer and accessed resources](investigate-a-computer.md). 
 
**Suggested remediation and steps for prevention** 
1. Contain the source computers 
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA.
    - If you have Windows Defender ATP installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.
2. Contain the resources that were accessed by this ticket.
3. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). 
    - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services will be broken and they will not work again until they are renewed or in some cases, the service is restarted. Plan carefully before performing the KRBTGT double reset, because it impacts all computers, servers and users in the environment.

 
## Suspected Golden Ticket usage (ticket anomaly) (external ID 2032) 

**Description**
Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence. Forged Golden Tickets of this type have unique characteristics this detection is specifically designed to identify.  
 
**TP, B-TP, or FP** 

Federation services might generate tickets that will trigger this alert. 
1. Does the source computer host Federation services that generate these types of tickets?  
    - If the source computer hosts services that generate these types of tickets, Close the security alert, as a **B-TP** activity.  
 
**Understand the scope of the breach**
1. Investigate the [source computer and accessed resources](investigate-a-computer.md). 
2. Investigate the [source user](investigate-a-user.md). 
 
**Suggested remediation and steps for prevention**

1. Contain the source computers 
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA.
    - If you have Windows Defender ATP installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.
2. Contain the resources that were accessed by this ticket.
3. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). 
   - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services are  broken and cannot work again until renewed or in some cases, the service is restarted. 

     **Plan carefully before performing a KRBTGT double reset. The reset impacts all computers, servers, and users in the environment.**

## Suspected Golden Ticket usage (time anomaly) (external ID 2022) 

Previous name: Kerberos golden ticket

**Description** 
Attackers with domain admin rights can compromise the KRBTGT account. Using the KRBTGT account, they can create a Kerberos ticket granting ticket (TGT) that provides authorization to any resource and set the ticket expiration to any arbitrary time. This fake TGT is called a "Golden Ticket" and allows attackers to achieve network persistence. This alert is triggered when a Kerberos ticket granting ticket is used for more than the allowed time permitted, as specified in the Maximum lifetime for user ticket. 
 
**TP, B-TP, or FP**
1. In the last few hours, was there any change made to the **Maximum lifetime for user ticket** setting in group policy, that might affect the alert?  
2. Is the Azure ATP Standalone Sensor involved in this alert a virtual machine? 
    - If the Azure ATP standalone sensor is involved, was it recently resumed from a saved state?  
3. Is there a time synchronization problem in the network, where not all of the computers are synchronized? 
    - Click the **Download details** button to view the Security Alert report Excel file, view the related network activities, and check if there is a difference between "StartTime" and "DomainControllerStartTime".

If the answer to the previous questions is **yes**, **Close** the security alert as a **B-TP** activity. 
 
**Understand the scope of the breach**
1. Investigate the [source computer and accessed resources](investigate-a-computer.md). 
2. Investigate the [compromised user](investigate-a-user.md). 
 
**Suggested remediation and steps for prevention** 
1. Contain the source computer. 
    - Find the tool that performed the attack and remove it.
    - Look for users logged on around the same time as the activity, as they may also be compromised. Reset their passwords and enable MFA.
    - If you have Windows Defender ATP installed – use **klist.exe purge** to delete all the tickets of the specified logon session and prevent future usage of the tickets.
2. Contain the resources accessed by this ticket.
3. Change the Kerberos Ticket Granting Ticket (KRBTGT) password twice according to the guidance in [KRBTGT Account Password Reset Scripts now available for customers](https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the KRBTGT account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). 
   - Resetting the KRBTGT twice invalidates all Kerberos tickets in this domain. Invalidating all Kerberos tickets in the domain means **all** services are broken, and won't work again until they are renewed or in some cases, the service is restarted. 

     **Plan carefully before performing a KRBTGT double reset. The reset impacts all computers, servers, and users in the environment.**

## Suspected skeleton key attack (encryption downgrade) (external ID 2010) 

*Previous name:* Encryption downgrade activity

**Description**
Encryption downgrade is a method of weakening Kerberos using a downgraded encryption level for different fields of the protocol that normally have the highest level of encryption. A weakened encrypted field can be an easier target to offline brute force attempts. Various attack methods utilize weak Kerberos encryption cyphers. In this detection, Azure ATP learns the Kerberos encryption types used by computers and users. The alert is issued when a weaker cypher is used that is unusual for the source computer, and/or user, and matches known attack techniques.  
 
Skeleton Key is malware that runs on domain controllers and allows authentication to the domain with any account without knowing its password. This malware often uses weaker encryption algorithms to hash the user's passwords on the domain controller. In this alert, the learned behavior of previous KRB_ERR message encryption from domain controller to the account requesting a ticket, was downgraded.
 
**Understand the scope of the breach**
1. Investigate the [domain controller](investigate-a-computer.md). 
2. Check if Skeleton Key has affected your domain controllers by [using the scanner written by the Azure ATP team](https://gallery.technet.microsoft.com/Aorato-Skeleton-Key-24e46b73).  
3. Investigate the [users](investigate-a-user.md) and [computers](investigate-a-computer.md) involved. 
 
**Suggested remediation and prevention steps**

1. Reset the passwords of the compromised users and enable MFA. 
2. Contain the domain controller. 
    - Remove the malware. For more information, see [Skeleton Key Malware Analysis](https://www.virusbulletin.com/virusbulletin/2016/01/paper-digital-bian-lian-face-changing-skeleton-key-malware).
    - Look for users logged on around the same time as the suspicious activity occurred, as they may also be compromised. Reset their passwords and enable MFA.

## Suspicious additions to sensitive groups (external ID 2024)

**Description** 
Attackers add users to highly privileged groups. Adding users is done to gain access to more resources, and gain persistency. This detection relies on profiling the group modification activities of users, and alerting when an abnormal addition to a sensitive group is seen. Azure ATP profiles continuously.  
 
For a definition of sensitive groups in Azure ATP, see [Working with the sensitive accounts](sensitive-accounts.md).
 
The detection relies on events audited on domain controllers. Make sure your domain controllers are [auditing the events needed](atp-advanced-audit-policy.md).
 
**Learning period**
<br>Four weeks per domain controller, starting from the first event.
 
**TP, B-TP, or FP**
<br>Legitimate group modifications that occur rarely and the system didn't learn as "normal", may trigger an alert. These alerts would be considered  **B-TP**. 
1. Is the group modification legitimate? 
    - If the group modification is legitimate, **Close** the security alert as a **B-TP** activity.
 
**Understand the scope of the breach** 
1. Investigate the users added to groups. 
    - Focus on their activities after they were added to the sensitive groups. 
2. Investigate the source user. 
    - Download the **Sensitive Group Modification** report to see what other modifications were made an who made them in the same time period. 
3. Investigate the computers the source user was logged into, around the time of the activity. 
  
**Suggested remediation and steps for prevention** 

**Remediation:**

1. Reset the password of the source user and enable MFA. 
    - Look for the computer the source user was active on. 
    - Check which computers the user was logged into around the same time as the activity. Check if these computers are compromised. 
    - If the users are compromised, reset their passwords and enable MFA. 

**Prevention:**

1. To help prevent future attacks, minimize the number of users authorized to modify sensitive groups. 
2. Set up Privileged Access Management for Active Directory if applicable.
 
## Suspicious service creation (external ID 2026)

*Previous name:* Suspicious service creation

**Description** 
A suspicious service has been created on a domain controller in your organization. This alert relies on event 7045 to identify this suspicious activity.  
 
**TP, B-TP, or FP**
<br>Some administrative tasks are legitimately performed against domain controllers by administrative workstations, IT team members, and service accounts. 

1. Is the source user/computer supposed to run these types of services on the domain controller?  
    - If the source user or computer is supposed to run these types of services, and should not continue to, **Close** the alert as a **B-TP** activity. 
    - If the source user or computer  is supposed to run these types of services, and should continue to, **Close** the security alert as a **B-TP** activity, and exclude that computer. 
 
**Understand the scope of the breach**
1. Investigate the [source user](investigate-a-user.md). 
2. Investigate the [destination computers](investigate-a-computer.md) the services were created on. 
  
**Suggested remediation and steps for prevention** 

**Remediation**
1. Reset the password of the source user and enable MFA. 
2. Contain the domain controllers.
    - Remediate the suspicious service.
    - Look for users logged on around the time of the activity, as they may also be compromised. Reset their passwords and enable MFA.
3. Locate the computer the source user was active on.         
    - Check the computers the user was logged into around the same time as the activity, and check if these computers are also compromised. 

**Prevention:**
1. Restrict remote access to domain controllers from non-Tier 0 machines. 
2. Implement [privileged access](https://docs.microsoft.com/windows-server/identity/securing-privileged-access/securing-privileged-access) to allow only hardened machines to connect to domain controllers for administrators.
3. Implement less-privileged access on domain machines to give only specific users the right to create services.

> [!div class="nextstepaction"]
> [Exfiltration alert tutorial](atp-exfiltration-alerts.md)
 
## See Also

- [Investigate a computer](investigate-a-computer.md)
- [Working with security alerts](working-with-suspicious-activities.md)
- [Working with lateral movement paths](use-case-lateral-movement-path.md)
- [Reconnaissance alerts](atp-reconnaissance-alerts.md)
- [Compromised credential alerts](atp-compromised-credentials-alerts.md)
- [Lateral movement alerts](atp-lateral-movement-alerts.md)
- [Exfiltration alerts](atp-exfiltration-alerts.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
