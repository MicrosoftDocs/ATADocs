---
# required metadata

title: ATA technical FAQ | Microsoft Advanced Threat Analytics
description: Provides a list of frequently asked questions about ATA and the associated answers
keywords:
author: rkarlin
manager: stevenpo
ms.date: 04/28/2016
ms.topic: article
ms.prod: identity-ata
ms.service: advanced-threat-analytics
ms.technology: security
ms.assetid: a7d378ec-68ed-4a7b-a0db-f5e439c3e852

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# ATA technical FAQ
This article provides a list of frequently asked questions about ATA and provides insight and answers.

## ATA Frequently Asked Questions


### What should I do if the ATA Gateway won’t start?
Look at the most recent error in the current error log (Where ATA is installed under the "Logs" folder).
### How can I test ATA?
You can simulate suspicious activities which is an end to end test by doing one of the following:<br /><br />1.  DNS reconnaissance by using Nslookup.exe<br />2.  Remote execution by using psexec.exe<br /><br />This needs to run against the domain controller being monitored and not from the ATA Gateway.
### How do I verify Windows Event Forwarding?
You can run the following from a command prompt in the directory:  **\Program Files\Microsoft Advanced Threat Analytics\Center\MongoDB\bin**:<br /><br />mongo ATA --eval "printjson(db.getCollectionNames())" &#124; find /C "NtlmEvents"`
### Does ATA work with encrypted traffic?
Encrypted traffic will not be analyzed (for example: LDAPS, IPSEC ESP).
### Does ATA work with Kerberos Armoring?
Enabling Kerberos Armoring, also known as Flexible Authentication Secure Tunneling (FAST), is supported by ATA, with the exception of over-pass the hash detection which will not work.
### How many ATA Gateways do I need?
There are two things to consider when figuring out how many gateways you would need:<br /><br />-   The total amount of traffic your domain controllers produce determines the minimum number of ATA Gateways you need in order to handle your Active Directory environment, from a performance perspective.<br />    To read more on how to determine how much traffic your domain controllers produce, see [ATA Capacity Planning](/advanced-threat-analytics/plan-design/ata-capacity-planning).<br />-   The operational limitations of port mirroring also determine how many ATA Gateways you need to support all your domain controllers, for example: per switch, per datacenter, per region – each environment has its own considerations.
### How much storage do I need for ATA?
For every one full day with an average of 1000 packets/sec you need 1.5 GB of storage.<br /><br />For more information see, [ATA Capacity Planning](/advanced-threat-analytics/plan-design/ata-capacity-planning).
### Why are certain accounts considered sensitive?
This happens when an account is a member of certain groups which we designate as sensitive (for example: "Domain Admins").<br />To understand why an account is sensitive you can review its group membership to understand which sensitive groups it belongs to (the group that it belongs to can also be sensitive due to another group, so the same process should be performed until you locate the highest level sensitive group).
### How do I monitor a virtual domain controller using ATA?
You can have either a virtual or physical ATA Gateways as described in [Configure port mirroring](/advanced-threat-analytics/plan-design/configure-port-mirroring).  <br />The easiest way is to have a virtual ATA Gateway on every host where a virtual domain controller exists.<br />If your virtual domain controllers move between hosts, you need to perform one of the following:<br /><br />-   When the virtual domain controller moves to another host, preconfigure the ATA Gateway in that host to receive the traffic from the recently moved virtual domain controller.<br />-   Make sure that you affiliate the virtual ATA Gateway with the virtual domain controller so that if it is moved, the ATA Gateway moves with it.<br />-   There are some virtual switches that can send traffic between hosts.
### How do I back up ATA?
There are 2 things to back up:<br />-   The traffic and events stored by ATA, which can be backed using any supported database backup procedure, for more information see [ATA database management](/advanced-threat-analytics/deploy-useata-database-management). <br />-   The configuration of ATA, which is stored in the database and is automatically backed up every hour. 
### What can ATA detect?
ATA detects known malicious attacks and techniques, security issues, and risks.
For the full list of ATA detections, see [What is Microsoft Advanced Threat Analytics?](/advanced-threat-analytics/understand-explore/what-is-ata).
### What kind of storage do I need for ATA?
We recommend fast storage (not 7200 RPM disks) with low latency numbers (less than 10 ms) and a RAID configuration that supports heavy write loads (not RAID-5/6 and their derivatives).
### How many NICs does the ATA Gateway require?
The ATA Gateway needs a minimum of two network adapters:<br>1. A NIC to connect to the internal network and the ATA Center<br>2. A NIC to capture the domain controller network traffic via port mirroring.<br>* This does not apply to the Lightweight Gateway
### What kind of integration does ATA have with SIEMs?
ATA has a bi-directional integration with SIEMs as follows:<br>
1. ATA can be configured to send a Syslog alert in the event of a suspicious activity to any SIEM server that supports CEF format.<br>2. ATA can be configured to receive Syslog messages for each Windows event with the ID 4776, from [these SIEMs](/advanced-threat-analytics/plan-design/configure-event-collection#configuring-the-ata-gateway-to-listen-for-siem-events.md).
