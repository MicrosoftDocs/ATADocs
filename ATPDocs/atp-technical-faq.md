---
# required metadata

title: Azure Advanced Threat Protection frequently asked questions | Microsoft Docs
description: Provides a list of frequently asked questions about Azure ATP and the associated answers
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 3/13/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 6a9b5273-eb26-414e-9cdd-f64406e24ed8

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

# Azure ATP frequently asked questions
This article provides a list of frequently asked questions about Azure ATP and provides insight and answers.


## Where can I get a license for Azure Advanced Threat Protection (ATP)?

You can acquire a license for Enterprise Mobility + Security 5 (EMS E5) directly via the [Office 365 portal](https://www.microsoft.com/cloud-platform/enterprise-mobility-security-pricing) or through the Cloud Solution Partner (CSP) licensing model.                  

## What should I do if the Azure ATP sensor or standalone sensor doesn't start?
Look at the most recent error in the current error log (Where Azure ATP is installed under the "Logs" folder).

## How can I test Azure ATP?
You can simulate suspicious activities as an end-to-end test, by running the following command:

-  DNS reconnaissance by using Nslookup.exe


This needs to run remotely against the domain controller being monitored and not from the Azure ATP standalone sensor.


## Does Azure ATP work with encrypted traffic?
Azure ATP relies on analyzing multiple network protocols, as well as events collected from the SIEM or via Windows Event Forwarding. Detections based on network protocols with encrypted traffic (for example, LDAPS and IPSEC) are not analyzed.


## Does Azure ATP work with Kerberos Armoring?
Enabling Kerberos Armoring, also known as Flexible Authentication Secure Tunneling (FAST), is supported by ATP, with the exception of over-pass the hash detection, which does not work with Kerberos Armoring.

## How many Azure ATP sensors do I need?

Every domain controller in the environment should be covered by an ATP sensor or standalone sensor. For more information, see [Azure ATP sensor Sizing](atp-capacity-planning.md#sizing). 


## Why are certain accounts considered sensitive?
This happens when an account is a member of groups that are designated as sensitive (for example: "Domain Admins").

To understand why an account is sensitive you can review its group membership to understand which sensitive groups it belongs to (the group that it belongs to can also be sensitive due to another group, so the same process should be performed until you locate the highest level sensitive group). You can also [tag accounts as sensitive manually](sensitive-accounts.md).

## How do I monitor a virtual domain controller using Azure ATP?
Most virtual domain controllers can be covered by the Azure ATP sensor, to determine whether the Azure ATP sensor is appropriate for your environment, see [Azure ATP Capacity Planning](atp-capacity-planning.md).

If a virtual domain controller can't be covered by the Azure ATP sensor, you can have either a virtual or physical Azure ATP standalone sensor as described in [Configure port mirroring](configure-port-mirroring.md).  <br />The easiest way is to have a virtual Azure ATP standalone sensor on every host where a virtual domain controller exists.<br />If your virtual domain controllers move between hosts, you need to perform one of the following steps:

-   When the virtual domain controller moves to another host, preconfigure the Azure ATP standalone sensor in that host to receive the traffic from the recently moved virtual domain controller.
-   Make sure that you affiliate the virtual Azure ATP standalone sensor with the virtual domain controller so that if it is moved, the Azure ATP standalone sensor moves with it.
-   There are some virtual switches that can send traffic between hosts.


## What can Azure ATP detect?

Azure ATP detects known malicious attacks and techniques, security issues, and risks.
For the full list of Azure ATP detections, see [What detections does Azure ATP perform?](suspicious-activity-guide.md).

## How many NICs does the Azure ATP standalone sensor require?
The Azure ATP standalone sensor needs a minimum of two network adapters:<br>1. A NIC to connect to the internal network and the Azure ATP cloud service<br>2. A NIC that is used to capture the domain controller network traffic via port mirroring.<br>* This does not apply to the Azure ATP sensor, which natively uses all of the network adapters that the domain controller uses.

## What kind of integration does Azure ATP have with SIEMs?
Azure ATP has a bi-directional integration with SIEMs as follows:

1. Azure ATP can be configured to send a Syslog alert, to any SIEM server using the CEF format, for health alerts and when a suspicious activity is detected.
2. Azure ATP can be configured to receive Syslog messages for Windows events from  [these SIEMs](configure-event-collection.md).

## How do I configure the Azure ATP sensors to communicate with Azure ATP cloud service when I have a proxy?

For your domain controllers to communicate with the cloud service, you must open: *.atp.azure.com port 443 in your firewall/proxy. For instructions on how to do this, see [Configure your proxy or firewall to enable communication with Azure ATP sensors](configure-proxy.md).
 

## Can Azure ATP monitor domain controllers virtualized on your IaaS solution?
Yes, you can use the Azure ATP sensor to monitor domain controllers that are in any IaaS solution.

## Is this going to be a part of Azure Active Directory or on-premises Active Directory?
This solution is currently a standalone offering. It is not a part of Azure Active Directory or on-premises Active Directory.

## Do you have to write your own rules and create a threshold/baseline?
With Azure Advanced Threat Protection, there is no need to create rules, thresholds, or baselines and then fine-tune. Azure ATP analyzes the behaviors among users, devices, and resources—as well as their relationship to one another—and can detect suspicious activity and known attacks fast. Three weeks after deployment, Azure ATP starts to detect behavioral suspicious activities. On the other hand, Azure ATP will start detecting known malicious attacks and security issues immediately after deployment.

## Does this only leverage traffic from Active Directory?
In addition to analyzing Active Directory traffic using deep packet inspection technology, Azure ATP also collects relevant events from your Security Information and Event Management (SIEM) and creates entity profiles based on information from Active Directory Domain Services. If you use the Azure ATP sensor, it extracts these events automatically. You can use Windows Event Forwarding to send these events to the Azure ATP standalone sensor. Azure ATP also supports receiving RADIUS accounting of VPN logs from various vendors (Microsoft, Cisco, F5, and Checkpoint).

## What is port mirroring?
Also known as SPAN (Switched Port Analyzer), port mirroring is a method of monitoring network traffic. With port mirroring enabled, the switch sends a copy of all network packets seen on one port (or an entire VLAN) to another port, where the packet can be analyzed.

## Does Azure ATP monitor only domain-joined devices?
No. Azure ATP monitors all devices in the network performing authentication and authorization requests against Active Directory, including non-Windows and mobile devices.

## Does Azure ATP monitor computer accounts as well as user accounts?
Yes. Since computer accounts (as well as any other entities) can be used to perform malicious activities, Azure ATP monitors all computer accounts behavior and all other entities in the environment.

## Can Azure ATP support multi-domain and multi-forest?
Azure Advanced Threat Protection supports multi-domain environments within the same forest boundary. Multiple forests require an Azure ATP workspace for each forest.

## Can you see the overall health of the deployment?
Yes, you can view the overall health of the deployment as well as specific issues related to configuration, connectivity etc., and you are alerted as they occur.

## What data does Azure ATP collect? 
Azure ATP collects and stores information from your configured servers (domain controllers, member servers, etc.) in a database specific to the service for administration, tracking, and reporting purposes. Information collected includes network traffic to and from domain controllers (such as Kerberos authentication, NTLM authentication, DNS queries), security logs (such as Windows security events), Active Directory information (structure, subnets, sites), and entity information (such as names, email addresses, and phone numbers). 

Microsoft uses this data to: 

-	Proactively identify indicators of attack (IOAs) in your organization 
-	Generate alerts if a possible attack was detected 
-	Provide your security operations with a view into entities related to threat signals from your network, enabling you to investigate and explore the presence of security threats on the network. 

Microsoft does not mine your data for advertising or for any other purpose other than providing you the service. 

## Do I have the flexibility to select where to store my data? 

When creating the Azure ATP workspace you can choose to store your data,  you can choose to store your data in Microsoft Azure data centers in either the United States or Europe. Once configured, you cannot change the location where your data is stored. Microsoft will not transfer the data from the specified location. 

## Is my data isolated from other customer data? 

Yes, your data is isolated through access authentication and logical segregation based on customer identifier. Each customer can only access data collected from their own organization and generic data that Microsoft provides. 

## How does Microsoft prevent malicious insider activities and abuse of high privilege roles? 

Microsoft developers and administrators have, by design, been given sufficient privileges to carry out their assigned duties to operate and evolve the service. Microsoft deploys combinations of preventive, detective, and reactive controls including the following mechanisms to help protect against unauthorized developer and/or administrative activity: 

-	Tight access control to sensitive data 
-	Combinations of controls that greatly enhance independent detection of malicious activity 
-	Multiple levels of monitoring, logging, and reporting 

In addition, Microsoft conducts background verification checks on certain operations personnel, and limits access to applications, systems, and network infrastructure in proportion to the level of background verification. Operations personnel follow a formal process when they are required to access a customer’s account or related information in the performance of their duties. 

## See Also
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)
