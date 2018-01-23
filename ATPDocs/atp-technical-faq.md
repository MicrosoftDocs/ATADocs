---
# required metadata

title: Azure Threat Protection frequently asked questions | Microsoft Docs
description: Provides a list of frequently asked questions about ATP and the associated answers
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 12/10/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
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
*Applies to: Azure Threat Protection *

# ATP frequently asked questions
This article provides a list of frequently asked questions about ATP and provides insight and answers.


## Where can I get a license for Azure Threat Protection (ATP)?

If you have an active Enterprise Agreement, you can download the software from the Microsoft Volume Licensing Center (VLSC).

If you acquired a license for Enterprise Mobility + Security (EMS) directly via the Office 365 portal or through the Cloud Solution Partner (CSP) licensing model and you do not have access to ATP through the Microsoft Volume Licensing Center (VLSC), contact Microsoft Customer Support to obtain the process to activate Azure Threat Protection (ATP).

## What should I do if the ATP Gateway won’t start?
Look at the most recent error in the current error log (Where ATP is installed under the "Logs" folder).

## How can I test ATP?
You can simulate suspicious activities which is an end to end test by doing one of the following:

1.  DNS reconnaissance by using Nslookup.exe
2.  Remote execution by using psexec.exe


This needs to run remotely against the domain controller being monitored and not from the ATP Gateway.

## Which ATP build corresponds to each version?

For version upgrade information, see [ATP upgrade path](upgrade-path.md).

## What version should I use to upgrade my current ATP deployment to the latest version?

For the ATP version upgrade matrix, see [ATP upgrade path](upgrade-path.md).


## How do I verify Windows Event Forwarding?
You can place the the following code into a file and then execute it from a command prompt in the directory:  **\Program Files\Microsoft Azure Threat Protection\Center\MongoDB\bin** as follows:

mongo.exe ATP filename

        db.getCollectionNames().forEach(function(collection) {
        if (collection.substring(0,10)=="NtlmEvent_") {
                if (db[collection].count() > 0) {
                                  print ("Found "+db[collection].count()+" NTLM events") 
                                }
                }
        });

## Does ATP work with encrypted traffic?
ATP relies on analyzing multiple network protocols, as well as events collected from the SIEM or via Windows Event Forwarding. Detections based on network protocols with encrypted traffic (for example, LDAPS and IPSEC) will not be analyzed.


## Does ATP work with Kerberos Armoring?
Enabling Kerberos Armoring, also known as Flexible Authentication Secure Tunneling (FAST), is supported by ATP, with the exception of over-pass the hash detection which will not work.

## How many ATP Gateways do I need?

The number of ATP Gateways depend on your network layout, volume of packets and volume of events captured by ATP. To determine the exact number, see [ATP Lightweight Gateway Sizing](ata-capacity-planning.md#ata-lightweight-gateway-sizing). 

## How much storage do I need for ATP?
For every one full day with an average of 1000 packets/sec you need 0.3 GB of storage.<br /><br />For more information about ATP Center sizing see, [ATP Capacity Planning](ata-capacity-planning.md).


## Why are certain accounts considered sensitive?
This happens when an account is a member of certain groups which we designate as sensitive (for example: "Domain Admins").

To understand why an account is sensitive you can review its group membership to understand which sensitive groups it belongs to (the group that it belongs to can also be sensitive due to another group, so the same process should be performed until you locate the highest level sensitive group).

## How do I monitor a virtual domain controller using ATP?
Most virtual domain controllers can be covered by the ATP Lightweight Gateway, to determine whether the ATP Lightweight Gateway is appropriate for your environment, see [ATP Capacity Planning](ata-capacity-planning.md).

If a virtual domain controller can't be covered by the ATP Lightweight Gateway, you can have either a virtual or physical ATP Gateway as described in [Configure port mirroring](configure-port-mirroring.md).  <br />The easiest way is to have a virtual ATP Gateway on every host where a virtual domain controller exists.<br />If your virtual domain controllers move between hosts, you need to perform one of the following steps:

-   When the virtual domain controller moves to another host, preconfigure the ATP Gateway in that host to receive the traffic from the recently moved virtual domain controller.
-   Make sure that you affiliate the virtual ATP Gateway with the virtual domain controller so that if it is moved, the ATP Gateway moves with it.
-   There are some virtual switches that can send traffic between hosts.

## How do I back up ATP?

Refer to [ATP disaster recovery](disaster-recovery.md)



## What can ATP detect?

ATP detects known malicious attacks and techniques, security issues, and risks.
For the full list of ATP detections, see [What detections does ATP perform?](ata-threats.md).

## What kind of storage do I need for ATP?
We recommend fast storage (7200-RPM disks are not recommended) with low latency disk access (less than 10 ms). The RAID configuration should support heavy write loads (RAID-5/6 and their derivatives are not recommended).

## How many NICs does the ATP Gateway require?
The ATP Gateway needs a minimum of two network adapters:<br>1. A NIC to connect to the internal network and the ATP Center<br>2. A NIC that is used to capture the domain controller network traffic via port mirroring.<br>* This does not apply to the ATP Lightweight Gateway, which natively uses all of the network adapters that the domain controller uses.

## What kind of integration does ATP have with SIEMs?
ATP has a bi-directional integration with SIEMs as follows:

1. ATP can be configured to send a Syslog alert, to any SIEM server using the CEF format, when a suspicious activity is detected.
2. ATP can be configured to receive Syslog messages for Windows events from  [these SIEMs](install-ata-step6.md).

## Can ATP monitor domain controllers virtualized on your IaaS solution?
Yes, you can use the ATP Lightweight Gateway to monitor domain controllers that are in any IaaS solution.

## Is this an on-premises or in-cloud offering?
Microsoft Azure Threat Protection is an on-premises product.

## Is this going to be a part of Azure Active Directory or on-premises Active Directory?
This solution is currently a standalone offering—it is not a part of Azure Active Directory or on-premises Active Directory.

## Do you have to write your own rules and create a threshold/baseline?
With Microsoft Azure Threat Protection, there is no need to create rules, thresholds, or baselines and then fine-tune. ATP analyzes the behaviors among users, devices, and resources—as well as their relationship to one another—and can detect suspicious activity and known attacks fast. Three weeks after deployment, ATP starts to detect behavioral suspicious activities. On the other hand, ATP will start detecting known malicious attacks and security issues immediately after deployment.

## If you are already breached, can Microsoft Azure Threat Protection identify abnormal behavior?
Yes, even when ATP is installed after you have been breached, ATP can still detect suspicious activities of the hacker. ATP is not only looking at the user’s behavior but also against the other users in the organization security map. During the initial analysis time, if the attacker’s behavior is abnormal, then it is identified as an “outlier” and ATP keeps reporting on the abnormal behavior. Additionally ATP can detect the suspicious activity if the hacker attempts to steal another users credentials, such as Pass-the-Ticket, or attempts to perform a remote execution on one of the domain controllers.

## Does this only leverage traffic from Active Directory?
In addition to analyzing Active Directory traffic using deep packet inspection technology, ATP can also collect relevant events from your Security Information and Event Management (SIEM) and create entity profiles based on information from Active Directory Domain Services. ATP can also collect events from the event logs if the organization configures Windows Event Log forwarding.

## What is port mirroring?
Also known as SPAN (Switched Port Analyzer), port mirroring is a method of monitoring network traffic. With port mirroring enabled, the switch sends a copy of all network packets seen on one port (or an entire VLAN) to another port, where the packet can be analyzed.

## Does ATP monitor only domain-joined devices?
No. ATP monitors all devices in the network performing authentication and authorization requests against Active Directory, including non-Windows and mobile devices.

## Does ATP monitor computer accounts as well as user accounts?
Yes. Since computer accounts (as well as any other entities) can be used to perform malicious activities, ATP monitors all computer accounts behavior and all other entities in the environment.

## Can ATP support multi-domain and multi-forest?
Microsoft Azure Threat Protection supports multi-domain environments within the same forest boundary. Multiple forests require an ATP deployment for each forest.

## Can you see the overall health of the deployment?
Yes, you can view the overall health of the deployment as well as specific issues related to configuration, connectivity etc., and you are alerted as they occur.


## See Also
- [ATP prerequisites](ata-prerequisites.md)
- [ATP capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)

