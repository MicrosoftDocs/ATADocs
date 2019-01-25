---
# required metadata

title: Azure ATP Reconnaissance playbook tutorial | Microsoft Docs
description: The Azure ATP Reconnaissance playbook tutorial describes how to simulate Reconnaissance threats for detection by Azure ATP.
ms.service: azure-advanced-threat-protection
ms.topic: tutorial
author: mlottner
ms.author: mlottner
ms.date: 01/22/2018

# optional metadata

# ms.custom
 ms.reviewer: itargoet
# ms.subservice
# ROBOTS

---

# Overview

The purpose of the Azure ATP Security Alert playbook is to illustrate **Azure ATP**'s capabilities in identifying and detecting suspicious activities and potential attacks against your network. The playbook explains how to test against some of Azure ATP's *discrete* detections, and focuses on Azure ATP’s *signature*-based capabilities. This playbook does not include alerts or detections based on advanced machine-learning, or user/entity based behavioral detections, as they require a learning period with real network traffic for up to 30 days.


## Lab Setup

Make sure your Azure ATP lab setup matches the lab setup reccomendation as closely as possible. The closer your lab is to the suggested lab setup, the easier it will be to follow the examples and results. 

![Azure ATP lab setup](media/playbook-atp-setup-lab.png)


# Executing a Reconnaissance attack

This Reconnaissance Playbook explains the process of how to use real-world, publicly available hacking and attack tools against threat detections and security alerts services of Azure ATP.

Other phases of the Azure ATP Attack Simulation Playbook:

- [Lateral Movement](atp-playbook-lateral-movement.md)
- [Domain Dominance](atp-playbook-domain-dominance.md)


## Reconnaissance

Once an adversary gains presence in your environment, their reconnaissance campaign begins. At this phase, the adversary will typically spend time researching, attempting to discover computers of interest, enumerate users and groups, gather important IPs, and map your organization's assets and weaknesses. Reconnaissance activities allow attackers to gain a thorough understanding and complete mapping of your environment for later use. 

Reconnaissance attack testing methods:

* [Network Mapping Recon](#Network-Mapping-Recon-(DNS))
* [Directory Service Reconnaissance](#directory-service-reconnaissance)
* [User and IP Address Recon (SMB)](#User-and-IP-Address-Recon-(SMB))

### Network Mapping Recon (DNS)

One of the first things an attacker will attempt is to try to get a dump of all DNS information. When successful, the attacker gains extensive information about your environment that potentially includes similar information about your other environments or networks.

To test DNS reconnaissance, we'll use the native Microsoft binary, *nslookup*. 

#### nslookup

>[!NOTE]
>Note DNS servers with correctly configuration will refuse queries of this type and not allow the zone transfer attempt.

1. Log into **VictimPC**, using the JeffL credentials compromised during [Azure ATP lab setup](atp-playbook-setup-lab.md). 
2. Run the following command:

``` cmd
nslookup
ls -d contoso.azure
```

![nslookup command attempt to dump the DNS server -failure](media/playbook-recon-nslookup.png)


#### Network Mapping Recon (DNS) Detected

Getting visibility of this type of attempt (failed or sucessful) is vital for domain threat protection. Azure ATP detects this type of reconnaissance against your DNS and issues the following security alert:

![DNS Recon detected by AATP--high level view](media/playbook-recon-nslookupdetection1.png)

Click on the security alert issued by Azure ATP to see additional details and evidence:

![Detailed view of the DNS recon detection in AATP](media/playbook-recon-nslookupdetection2.png)

>[!NOTE]
>If your security analyst determined this activity originated from a security scanner, the specific device can be excluded from further alerts for the detection. On the top right area of the alert, click on the three dots and select **Close and exclude VictimPC**. Ensuring this alert doesn't show up again when detected from "VictimPC".

Detecting failures can be just as insightful as detecting successful attacks against an environment. Azure ATP portal allows us to see the exact result of the action(s) performed by the possible attacker.

In our simulated DNS reconnaissance attack story, we, as attackers, were stopped from dumping the DNS records of the domain and the SecOps team became aware of our attempted attack and which machine we used in our attempt from the Azure ATP security alert. 

### Directory Service Reconnaissance

As the attacker, the next reconnaissance goal is an attempt to enumerate all users and groups in the Forest.

To demonstrate this reconnaissance method, we'll use the native Microsoft binary, *net*.   After our attempt, examining the Activity timeline of JeffL--our compromised user--will show Azure ATP detecting this activity.

>[!NOTE]
>Azure ATP suppresses Directory Service enumeration activity from your Suspicious Activity timeline until a 30 day learning period is completed. In the 30 day learning period, Azure ATP learns what is normal and abnormal for your network. After the 30 day learning period, abnormal Directory Service enumeration events invoke a security alert. However, during the 30 day learning period, (exactly as shown in this lab), you can see Azure ATP detections of these types of activities using the activity timeline of any entity in your network.

#### Directory Service Enumeration via *net*

Any authenticated user or computer can potentially enumerate other users and groups in a domain. This enumeration ability is required for most applications to function properly. Our compromised user, JeffL, is an unprivileged domain account. In this attack, we'll see exactly how even an unprivildeged domain account can still provide valuable data points to an attacker. 

1. From **VictimPC**, execute the following command:

``` cmd
net user /domain
```

The output shows all users in the Contoso.Azure domain.

![Enumerate all users in the domain](media/playbook-recon-dsenumeration-netusers.png)

Next, let's try to enumerate all groups in the domain: 
1. To attempt to get all groups in the domain, excute the following command: 

``` cmd
net group /domain
```

The output shows all groups in the Contoso.Azure domain. Notice the one Security Group that isn't there by default, **Helpdesk**.

![Enumerate all groups in the domain](media/playbook-recon-dsenumeration-netgroups.png)

Now, let's attempt to enumerate only the Domain Admins group.
1. To attempt to enumerate all Domain Admins in the domain, execute the following command:

``` cmd
net group "Domain Admins" /domain
```

![Enumerate all members of the Domain Admins group](media/playbook-recon-dsenumeration-netdomainadmins.png)

As the attacker, we've learned there are two members of the Domain Admins group: **SamiraA** and **ContosoAdmin** (built-in Administrator for the Domain Controller).

Knowing no security boundary exists between the Domain and Forest, our next leap is to try to enumerate the Enterprise Admins.

1. To attempt to enumerate the enterprise Admins, execute the following command:

``` cmd
net group "Enterprise Admins" /domain
```

We learned that there is only one Enterprise Admin, ContosoAdmin. This wasn't particularly important as there is anyway [no security boundary between a Domain and the Forest](https://technet.microsoft.com/en-us/library/2006.05.smarttips.aspx).

![Enterprise Admins enumerated in the domain](media/playbook-recon-dsenumeration-netenterpriseadmins.png)

However, with the information gathered in our reconnaissance  information, we now know about the Helpdesk Security Group--although that isn't particularly interesting *yet*. We also know that **SamiraA** is a member of the Domain Admins group--if we can harvest SamiraA's credential we can gain access the Domain Controller itself!

#### Directory Service Enumeration Detected

If our lab had *real live activity for 30 days with Azure ATP installed*, the activity we just performed as JeffL would potentially be classified as abnormal and thus show up in the Suspicious Activity timeline.  However, since we just installed the environment, we will need to go to the Logical Activities timeline.

In the Azure ATP Search, let's see what JeffL's Logical Activity timeline looks like:

![Search the logical activity timeline for a specific entity](media/playbook-recon-dsenumeration-searchlogicalactivity.png)

We can see when JeffL signed onto the VictimPC, using the Kerberos protocol. In addition, we see that JeffL, from VictimPC, enumerated all the users in the domain.

![JeffL's logical activity timeline](media/playbook-recon-dsenumeration-jeffvlogicalactivity.png)

Many activities are logged in the Logical Activity timeline making the Logical Activity timeline a major capability to performing Digital Forensics and Incident Response (DFIR)--even when the initial detection wasn't from Azure ATP (i.e. Windows Defender ATP, Office 365, etc.).

Taking a look at ContosoDC's page, we can also see the computers he logged into.

![JeffL logged on computers](media/playbook-recon-dsenumeration-jeffvloggedin.png)

We can even get Directory Data, including his Memberships and Access Controls, all from within Azure ATP.

![JeffL's directory data in AATP](media/playbook-recon-dsenumeration-jeffvdirectorydata.png)

Now, our attention will be shift towards SMB Session Enumeration.

### User and IP Address Recon (SMB)

Active Directory’s SYSVOL is one of the, if not *the*, most important network share in the environment. Every computer and user must be able to access this particular network share to pull down Group Policies. An attacker can get a goldmine of information from enumerating who has active sessions with the sysvol folder.

Let’s perform SMB Session Enumeration against the ContosoDC resource so we can learn who else has sessions with the SMB Share, and *from what IP*.

#### JoeWare’s NetSess.exe

Using JoeWare’s **NetSess** tool, lets run it against ContosoDC in context of an authenticated user (in this case, ContosoDC):

``` cmd
NetSess.exe ContosoDC
```

![Attackers use SMB Recon to identify users and their IP addresses](media/playbook-recon-smbrecon.png)

We already knew that SamiraA is a Domain Admin. This attack gave us the IP address of SamiraA (10.0.24.6).

As the attacker, we learned exactly who we need to compromise, and got the network location where that credential is logged in. 

#### User and IP Address Recon (SMB) Detected

Let’s see what Azure ATP detected for us:

![AATP Detecting SMB Recon](media/playbook-recon-smbrecon-detection1.png)

Not only are we alerted on this activity, we are also alerted on the exposed accounts and their respective IP addresses *at that point in time*. As the Security Operations Center (SOC), we don't just have the attempt and its status, but also what was sent back to the attacker. We could use this information to aid our investigation.

The next phase in the attack kill chain is typically an attempt at lateral movement. See [Azure ATP Lateral Movement playbook](atp-playbook-lateral-movement.md) for examples.  

## Join the Community

Have more questions, or an interest in discussing Azure ATP and related security with others? Join the [Azure ATP Community](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection) today!

## See Also
* [Azure ATP Lateral Movement playbook](atp-playbook-lateral-movement.md)
* [Azure ATP Domain Dominance playbook](atp-playbook-domain-dominance.md)
* [Azure ATP security alert guide](suspicious-activity-guide.md)
* [Investigate lateral movement paths with Azure ATP](use-case-lateral-movement-path.md)
* [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
