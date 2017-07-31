---
# required metadata

title: ATA suspicious activity guide | Microsoft Docs
d|Description: This article provides a list of the suspicious activities ATA can detect and steps for remediation.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 07/31/2017
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


# Introduction

ATA provides detection for the following various phases of an advanced attack:
reconnaissance, credential compromise, lateral movement, privilege escalation,
domain dominance, and others.

The phases in the kill-chain where ATA currently provides detections are highlighted in this diagram.

![ATA focus on lateral activity in attack kill chain](media/attack-kill-chain-small.jpg)

This article provides details about each suspicious activity per phase.


## Reconnaissance using account enumeration

> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Account enumeration attack is a technique attackers use to guess different account names, using Kerberos authentication attempts, to discover if a user exists in the network. Successfully guessed accounts can be used in subsequent steps of the attack. | Look at the computer in question and try to determine if there is a legitimate reason why it would start so many Kerberos authentication processes. These are processes that tried and failed to learn multiple accounts, because the user doesn't exist, (Client_Principal_Unknown error) and at least one access attempt that succeed. <br></br>**Exceptions:** This detection relies on finding multiple non-existing accounts and attempting authentication from a single computer. If a user makes a mistake while manually typing a username or a domain, the authentication attempt is seen as an attempt to log on to a non-existing account. Terminal servers that require many users to log in might legitimately have a large number of mistaken log in attempts. |Investigate the process responsible for generating these requests.  For help identifying processes based on source port, see [Have you ever wanted to see which Windows process sends a certain packet out to network?](https://blogs.technet.microsoft.com/nettracer/2010/08/02/have-you-ever-wanted-to-see-which-windows-process-sends-a-certain-packet-out-to-network/)|Medium|

## Reconnaissance using directory services enumeration (SAM-R)

> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
irectory services reconnaissance is a technique used by attackers to map the directory structure and target privileged accounts for later steps of the attack. The Security Account Manager Remote (SAM-R) protocol is one of the methods used to query the directory. | Understand why the computer in question is performing Security Accounts Manager - Remote (MS-SAMR). This is being performed in an abnormal way, likely querying sensitive entities. <br></br>**Exceptions:** This detection relies on profiling the normal behavior of users who make SAM-R queries, and alerting you when an abnormal query is observed. Sensitive users who log in to computers that they do not own may trigger a SAM-R query that will be detected as abnormal, even if it is a part of the normal work process. This can commonly happen to members of the IT team. If this is flagged as suspicious but was the result of normal use, it is because the behavior was not formerly observed by ATA. | In this case, it is recommended to have a longer learning period and better coverage of ATA in the domain, per Active Directory forest.<br></br>[Download and run the “SAMRi10” tool](https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b). SAMRi10 was releasesd by the ATA team, which hardens your environment against SAM-R queries. | Medium|

## Reconnaissance using DNS


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Your DNS server contains a map of all the computers, IP addresses and services in your network. This information is used by attackers to map your network structure and target interesting computers for later steps in their attack. | Understand why the computer in question is performing a Full Transfer Zone (AXFR) query to get all the records in the DNS domain. <br></br>**Exceptions:** This detection identifies non-DNS servers that issue DNS zone transer requests. There are several security scanner solutions that are known to issue these kinds of requests to DNS servers. <br></br>Also, verify ATA is able to communicate via port 53 from the ATA Gateways to the DNS servers to avoid false positive scenarios.| Limit Zone Transfer by carefully choosing which hosts can request it. For more details see [Securing DNS](https://technet.microsoft.com/library/cc770474(v=ws.11).aspx) and [Checklist: Secure Your DNS Server](https://technet.microsoft.com/library/cc770432(v=ws.11).aspx). |Medium|

## Reconnaissance using SMB Session Enumeration


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Server Message Block (SMB) enumeration enables an attacker to get information about which IP addresses users in your network recently logged on from. Once an attacker has this information, they can use it to target specific accounts and move around laterally in the network. | Understand why the computer in question is performing SMB Session enumerations.<br></br>**Exceptions:** This detection relies on the assumption that SMB session enumeration has no legitimate use in an enterprise network, but some security scanner solutions (such as Websense) issue such requests. | [Use the net cease tool to harden your environment](https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b) | Medium   |

## Brute-force (LDAP, Kerberos, NTLM)


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| In a brute-force attack, an attacker tries many passwords, hoping to eventually guess correctly. The attacker systematically checks all possible passwords (or a large set of possible passwords) until the correct one is found. After an attacker guesses the correct password, they can login to the network as if they were the user. Currently ATA supports horizontal (multiple accounts) brute-force using the Kerberos or NTLM protocol, and horizontal and vertical (single account, multiple password attempts) using LDAP simple bind. | Understand why the computer in question might be failing to authenticate multiple user accounts (having roughly the same number of authentication attempts for multiple users) or why there was a large number of authentication failures for a single user. <br></br>**Exceptions:** This detection relies on profiling the normal behavior of accounts that authenticate to different resources, and alert is triggered when an abnormal pattern is observed. This pattern is not uncommon in scripts that authenticate automatically but might use outdated credentials (i.e. wrong password or user name). | Complex and long passwords provide a the necessary first level of security against brute-force attacks. | Medium   |

## Sensitive account exposed in plain text authentication and Service exposing accounts in plain text authentication


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Some services on a computer send account credentials in plain text, even for sensitive accounts. Attackers monitoring your traffic can catch hold of these credentials for malicious purposes. Any clear text password of a sensitive account will trigger the alert. | Find the perpetrating computer and find out why it’s using LDAP simple binds. | Verify the configuration on the source computers and make sure not to use LDAP simple bind. Instead of using LDAP simple binds use LDAP SALS or LDAPS. Follow the Security Tiered Framework and restrict access across the tiers to prevent privilege escalation. | Low for service exposing; Medium for sensitive accounts |

## Honey Token account suspicious activities


> [!div class="mx-tableFixed"]
|D|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Honey Token accounts are decoy accounts set up to trap, identify, and track malicious activity in the network that involves these accounts. These are accounts that are unused and dormant on your network, and if there is suddenly activity from a honey token account, it can indicate that a malicious user is attempting to use this account. | Understand why a honey token account be authenticating from this computer. | Browse through the ATA profile pages of other sensitive (privileged) accounts in your environment to see if there are potentially suspicious activities. | Medium   |

## Unusual protocol implementation


> [!div class="mx-tableFixed"]
|D|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
|Attackers can use tools that implement SMB/Kerberos protocols in certain ways that enable them to achieve capabilities over your network. This is indicative of malicious techniques used for over-pass-the-hash or brute force attacks. | Understand why the computer in question would use an authentication protocol or SMB in an unusual way. <br></br>To determine whether this is a WannaCry attack, do this:<br></br> 1.	Download the Excel export of the suspicious activity.<br></br>2.	Open the network activity tab and go to the "Json" field to copy the related Smb1SessionSetup & Ntlm JSONs<br></br>3.	If the Smb1SessionSetup.OperatingSystem is "Windows 2000 2195" & the Smb1SessionSetup.IsEmbeddedNtlm is "true" and if the Ntlm.SourceAccountId is "null" then this is WannaCry.<br></br><br></br>**Exceptions:** This detection might be triggered in rare cases when legitimate tools are used that implement the protocols in a non-standard way. Some pen testing applications are known to do this. | Capture network traffic and identify which process is generating traffic with the unusual protocol implementation.| Medium|

## Malicious Data Protection Private Information Request


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
|The Data Protection API (DPAPI) is used by several components of Windows to securely store passwords, encryption keys and other sensitive data. Domain controllers hold a backup master key that can be used to decrypt all secrets encrypted with DPAPI by domain-joined Windows machines. Attackers can use the DPAPI domain backup master key to decrypt all secrets on all domain-joined machines (browser passwords, encrypted files, etc.).| Understand why the computer made a request using this undocumented API call for the master key for DPAPI.|Read more about DPAPI in [Windows Data Protection](https://msdn.microsoft.com/library/ms995355.aspx).|High|

## Suspicion of identity theft based on abnormal behavior


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| After building a behavioral model (it takes at least 50 active accounts over the course of 3 weeks to build a behavioral model), any abnormal behavior will trigger an alert. Behavior that does not match the model built for a specific user account could point to identity theft. | Understand why the user in question might be behaving differently. <br></br>**Exceptions:** If ATA only has partial coverage (not all domain controllers are routed to an ATA Gateway), then only partial activity is learned for a specific user. If suddenly, after more than 3 weeks, ATA starts covering all your traffic, full activity of the user could cause the alert to be triggered. | Make sure ATA is deployed on all your domain controllers. <br></br>1.  Check if the user has a new position in the organization.<br></br>2.  Check if the user is a seasonal worker.<br></br>3.  Check if the user just returned after a long absence.| Medium for all users and High for sensitive users |


## Pass the ticket


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| A Pass-the-Ticket attack is a lateral movement technique in which attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by impersonating an entity on your network. | This detection relies on the use of the same Kerberos tickets on two (or more) different computers. In some cases, if your IP addresses change rapidly, ATA might not be able to determine if different IP addresses are used by the same computer, or by different computers. This is a common issue with undersized DHCP pools (VPN, WiFi, etc.) and shared IP addresses (NAT devices). | Follow the Security Tiered Framework and restrict access across tiers to prevent privilege escalation. | High     |

## Pass the hash


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| In a pass the hash attack the attacker authenticates to a remote server or service by using the underlying NTLM hash of a user's password, instead of the associated plaintext password as is normally the case. | See if the account performed any abnormal activities in the timeperiod around this alert. | Implement the recommendations described in [Pass the Hash](http://aka.ms/PtH). Follow the Security Tiered Framework and restrict access across tiers to prevent privilege escalation. | High|

## Over-pass the hash


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| An Over pass the hash attack exploits an implementation weakness in the Kerberos authentication protocol, where an NTLM hash is used to create a Kerberos ticket, allowing an attacker to authenticate to services in the network without the user's password. | Encryption downgrade: Understand why the account in question might be using RC4 in Kerberos after it learned to use AES. <br></br>**Exceptions:** This detection relies on profiling encryption methods used in the domain, and alerting you if an abnormal and weaker method is observed. In some cases, a weaker encryption method will be used and ATA will detect it as abnormal, although it might be part of your normal (though rare) work process. This can happen when such behavior was not formerly observed by ATA. Better coverage of ATA in the domain will help. | Implement the recommendations described in [Pass the Hash](http://aka.ms/PtH). Follow the Security Tiered Framework and restrict access across tiers to prevent privilege escalation. | High     |

## Privilege escalation using forged authorization data (MS14-068 exploit (Forged PAC) / MS11-013 exploit (Silver PAC))


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Known vulnerabilities in older versions of Windows Server allow attackers to manipulate the Privileged Attribute Certificate (PAC), a field in the Kerberos ticket that contains a user's authorization data (in Active Directory this is group membership), granting an attacker additional privileges. | Check if there is a special service running on the affected computer that might use an authorization method other than PAC. <br></br>**Exceptions:** In some specific scenarios, resources implement their own authorization mechanism, and may trigger an alert in ATA. | Make sure all domain controllers with operating systems up to Windows Server 2012 R2 are installed with [KB3011780](https://support.microsoft.com/help/2496930/ms11-013-vulnerabilities-in-kerberos-could-allow-elevation-of-privilege) and all member servers and domain controllers up to 2012 R2 are up-to-date with KB2496930. For more information, see [Silver PAC](https://technet.microsoft.com/library/security/ms11-013.aspx) and [Forged PAC](https://technet.microsoft.com/library/security/ms14-068.aspx). | High     |

## Abnormal Sensitive Group Modification


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
|As part of the privilege escalation phase, attackers modify groups with high privileges to gain access to sensitive resources.| Validate that the group change is legitimate. <br></br>**Exceptions:** The detection relies on profiling the normal behavior of users who modify sensitive groups, and alerting you when an abnormal change is observed. Legitimate changes might trigger an alert when such behavior was not formerly observed by ATA. Longer learning period and better coverage of ATA in your domain will help. | Make sure to minimize the group of people who are authorized to modify sensitive groups. Use Just-I- Time permissions if possible. | Medium   |

## Encryption downgrade - Skeleton Key Malware


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| The Skeleton Key is malware that runs on domain controllers and allows authentication to the domain with any account without knowing its password. This malware often uses weaker encryption algorithms to encipher the user's passwords on the domain controller. | Encryption downgrade: Understand why the account in question might be using RC4 in Kerberos after it learned to use AES. <br></br>**Exceptions:** This detection relies on profiling encryption methods used in the domain. In some cases, a weaker encryption method will be used and ATA will detect it as abnormal, although it is a part of the normal (though rare) work process. | You can check if Skeleton Key has affected your domain controllers by using [the scanner written by the ATA team](https://gallery.technet.microsoft.com/Aorato-Skeleton-Key-24e46b73). | High |

## Golden ticket


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| If an attacker has domain admin rights, they can create a Kerberos ticket granting ticket (TGT) that provides authorization for all resources in the network, and sets the ticket expiration time to whenever they choose. This allows attackers to achieve persistency in the network. | Encryption downgrade: Understand why the account in question might be using RC4 in Kerberos after it learned to use AES. <br></br>**Exceptions:** This detection relies on profiling encryption methods used in the domain, and sending an alert when an abnormal and weaker method is observed. In some cases, a weaker encryption method is be used and ATA will detect it as abnormal, even if it is a part of the normal (though rare) work process. This can happen when such behavior was not formerly observed by ATA. Make sure ATA has full coverage of your domain. | Keep the master key Kerberos Ticket Granting Ticket (KRBTGT) as secure as possible, in the following ways:<br></br>1.  Physical security<br></br>2.  Physical security for virtual machines<br></br>3. Perform domain controller hardening<br></br>4.  Local Security Authority (LSA) Isolation/Credential Guard<br></br>If golden tickets are detected, a deeper investigation needs to be conducted to evaluate whether tactical recovery is needed.<br></br>Change the Kerberos Ticket Granting Ticket (KRBTGT) twice regularly according to the guidance on the [Microsoft blog, KRBTGT Account Password Reset Scripts now available for customers](https://blogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/), using the [Reset the krbtgt account password/keys tool](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51). <br></br>Implement these [Pass the hash recommendations](http://aka.ms/PtH). | Medium   |



## Remote execution


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Attackers who compromised administrator credentials can execute remote commands on your domain controller. This can be used for gaining persistency, collecting information, denial of service (DOS) attacks or any other reason. | Find out whether the account in question is allowed to perform this remote execution against your domain controller. <br></br>**Exceptions:** Legitimate users who sometimes run commands on the domain controller may trigger this alert, although it is a part of the normal administration process. This is most common for IT team members or service accounts that perform administrative tasks against the domain controllers. | Restrict remote access to domain controllers from non-Tier 0 machines. Delete any suspicious, stale and not required files and folders. Implement strong User Account Control (UAC) policies. Implement [PAW](https://technet.microsoft.com/en-us/windows-server-docs/security/securing-privileged-access/securing-privileged-access) to allow only hardened machines to connect to domain controllers for admins. | Low      |

## Malicious replication requests


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Active Directory replication is the process by which the changes that are made on one domain controller are synchronized with all other domain controllers in the domain or forest that store copies of the same data. Given appropriate permission, an attacker can initiate a replication request as if they were a domain controller, allowing the attacker to retrieve the data stored in Active Directory, including password hashes. | Understand why the computer might be using the domain controller replication API. This detection relies on ATA using the configuration partition of the directory forest to understand whether a computer is a domain controller. <br></br>**Exceptions::** Azure AD Dir Sync might cause this alert to be triggered. | Validate the following permissions: -   Replicate Directory Changes <br></br>-   Replicate Directory Changes Al<br></br>For more information see [Grant Active Directory Domain Services permissions for profile synchronization in SharePoint Server 2013](https://technet.microsoft.com/library/hh296982.aspx)<br></br>You can leverage [AD ACL Scanner](https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/) or create a PowerShell script to determine who in the domain has these permissions. | Medium   |



## Broken trust between domain and computers


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| Broken trust means that Active Directory security requirements may not be in effect. This is often considered a baseline security and compliance failure and a soft target for attackers. This will trigger an alert in ATA if more than 5 consecutive Kerberos authentication failures are seen from a computer account in the span of 24 hours. Since the computer is not communicating with the domain controller then (1) it has no updated group policy and (2) logging in is limited to the cached credentials. | Make sure the computer trust with the domain is healthy by checking the event logs. | Join the machine back to the domain if required or reset the machine's password. | Low      |

## Massive object deletion


> [!div class="mx-tableFixed"]
|Description|Investigation|Recommendation|Severity|
|------|----|------|----------|
| ATA raises this alert when more than 5% of all accounts are deleted. This requires read access to the deleted item container. | Understand why 5% of all your accounts were suddenly deleted. | Remove permissions for users who can delete accounts in Active Directory. For more details, see [View or Set Permissions on a Directory Object](https://technet.microsoft.com/library/cc816824%28v=ws.10%29.aspx). | Low |

## See Also
- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Investigating Forged PAC attacks](use-case-forged-pac.md)
- [Troubleshooting ATA known errors](troubleshooting-ata-known-errors.md)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
