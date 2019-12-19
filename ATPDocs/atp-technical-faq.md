---
# required metadata

title: Azure Advanced Threat Protection frequently asked questions | Microsoft Docs
description: Provides a list of frequently asked questions about Azure ATP and the associated answers
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 10/16/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
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
# Azure ATP frequently asked questions
This article provides a list of frequently asked questions and answers about Azure ATP divided into the following categories: 
- [What is Azure ATP](#what-is-azure-atp)
- [Licensing and privacy](#licensing-and-privacy)
- [Deployment](#deployment)
- [Operations](#operation)
- [Troubleshooting](#troubleshooting)

## What is Azure ATP?

### What can Azure ATP detect?

Azure ATP detects known malicious attacks and techniques, security issues, and risks against your network.
For the full list of Azure ATP detections, see [What detections does Azure ATP perform?](suspicious-activity-guide.md).

### What data does Azure ATP collect? 

Azure ATP collects and stores information from your configured servers (domain controllers, member servers, etc.) in a database specific to the service for administration, tracking, and reporting purposes. Information collected includes network traffic to and from domain controllers (such as Kerberos authentication, NTLM authentication, DNS queries), security logs (such as Windows security events), Active Directory information (structure, subnets, sites), and entity information (such as names, email addresses, and phone numbers). 

Microsoft uses this data to: 

-	Proactively identify indicators of attack (IOAs) in your organization 
-	Generate alerts if a possible attack was detected 
-	Provide your security operations with a view into entities related to threat signals from your network, enabling you to investigate and explore the presence of security threats on the network. 

Microsoft does not mine your data for advertising or for any other purpose other than providing you the service. 

### Does Azure ATP only leverage traffic from Active Directory?

In addition to analyzing Active Directory traffic using deep packet inspection technology, Azure ATP also collects relevant Windows Events from your domain controller and creates entity profiles based on information from Active Directory Domain Services. Azure ATP also supports receiving RADIUS accounting of VPN logs from various vendors (Microsoft, Cisco, F5, and Checkpoint).

### Does Azure ATP monitor only domain-joined devices?

No. Azure ATP monitors all devices in the network performing authentication and authorization requests against Active Directory, including non-Windows and mobile devices.

### Does Azure ATP monitor computer accounts as well as user accounts?

Yes. Since computer accounts (as well as any other entities) can be used to perform malicious activities, Azure ATP monitors all computer accounts behavior and all other entities in the environment.

### What is the difference between Advanced Threat Analytics (ATA) and Azure ATP?

ATA is a standalone solution, installed on-premises. Azure ATP with its cloud connectivity includes continuous feature updates including new detections, UEBA capabilities, security assessments, and an investigation experience across Microsoft 365 Security solutions.


Azure ATP’s additional capabilities: 
- Azure ATP detects more on-premises suspicious behavior and advanced attacks than ATA, and provides **identity security assessment** reports.
- Re-architected sensor with additional data sources (such as **Event Tracing for Windows**). 
- Azure ATP protects multi-forest environments. 

Azure ATP is a part of Microsoft 365 Security – securing the hybrid organization:
- Azure ATP, together with Microsoft Cloud App Security (MCAS) and Azure AD Identity Protection, provides a unified investigation experience for user activities, on-premises and in the cloud, and provides enhanced User and Entity Behavior Analytics (UEBA) detections.
- ATA has no integration with other Microsoft online security solutions 
  
Scalable and secure, leveraging the power of the cloud: 
- Azure ATP allows customers to enjoy the benefits of a cloud based solution, with no scaling limitations and continuous updates. 
- ATA is based on an on-premises, central management server that requires dedicated hardware for the central management center to be deployed on-premises, and typically receives one or two version updates annually.


## Licensing and privacy 

### Where can I get a license for Azure Advanced Threat Protection (ATP)?

Azure ATP is available as part of Enterprise Mobility + Security 5 suite (EMS E5), and as a standalone license. You can acquire a license directly from the [Microsoft 365 portal](https://www.microsoft.com/cloud-platform/enterprise-mobility-security-pricing) or through the Cloud Solution Partner (CSP) licensing model.

### Does Azure ATP need only a single license or does it require a license for every user I want to protect?

Azure ATP requires licensing for every user. 

### Is this going to be a part of Azure Active Directory or on-premises Active Directory?

The Azure ATP solution is currently a standalone offering. It is not a part of Azure Active Directory or on-premises Active Directory.

### Is my data isolated from other customer data? 

Yes, your data is isolated through access authentication and logical segregation based on customer identifiers. Each customer can only access data collected from their own organization and generic data that Microsoft provides.

### Do I have the flexibility to select where to store my data? 

No. When your Azure ATP instance is created, it is stored automatically in the country data center closest to the geographical location of your AAD tenant. Azure ATP data cannot be moved once your Azure ATP instance is created to a different data center.                

### How does Microsoft prevent malicious insider activities and abuse of high privilege roles? 

Microsoft developers and administrators have, by design, been given sufficient privileges to carry out their assigned duties to operate and evolve the service. Microsoft deploys combinations of preventive, detective, and reactive controls including the following mechanisms to help protect against unauthorized developer and/or administrative activity: 

-	Tight access control to sensitive data 
-	Combinations of controls that greatly enhance independent detection of malicious activity 
-	Multiple levels of monitoring, logging, and reporting 

In addition, Microsoft conducts background verification checks on certain operations personnel, and limits access to applications, systems, and network infrastructure in proportion to the level of background verification. Operations personnel follow a formal process when they are required to access a customer’s account or related information in the performance of their duties. 

## Deployment

### How many Azure ATP sensors do I need?

Every domain controller in the environment should be covered by an ATP sensor or standalone sensor. For more information, see [Azure ATP sensor sizing](atp-capacity-planning.md#sizing). 

### Does Azure ATP work with encrypted traffic?
Network protocols with encrypted traffic (for example, AtSvc and WMI) are not decrypted, but are analyzed by the sensors.

### Does Azure ATP work with Kerberos Armoring?
Enabling Kerberos Armoring, also known as Flexible Authentication Secure Tunneling (FAST), is supported by Azure ATP, with the exception of over-pass the hash detection, which does not work with Kerberos Armoring.

### How do I monitor a virtual domain controller using Azure ATP?
Most virtual domain controllers can be covered by the Azure ATP sensor, to determine whether the Azure ATP sensor is appropriate for your environment, see [Azure ATP Capacity Planning](atp-capacity-planning.md).

If a virtual domain controller can't be covered by the Azure ATP sensor, you can have either a virtual or physical Azure ATP standalone sensor as described in [Configure port mirroring](configure-port-mirroring.md).  <br />The easiest way is to have a virtual Azure ATP standalone sensor on every host where a virtual domain controller exists.<br />If your virtual domain controllers move between hosts, you need to perform one of the following steps:

-   When the virtual domain controller moves to another host, preconfigure the Azure ATP standalone sensor in that host to receive the traffic from the recently moved virtual domain controller.
-   Make sure that you affiliate the virtual Azure ATP standalone sensor with the virtual domain controller so that if it is moved, the Azure ATP standalone sensor moves with it.
-   There are some virtual switches that can send traffic between hosts.

### How do I configure the Azure ATP sensors to communicate with Azure ATP cloud service when I have a proxy?

For your domain controllers to communicate with the cloud service, you must open: *.atp.azure.com port 443 in your firewall/proxy. For instructions on how to do this, see [Configure your proxy or firewall to enable communication with Azure ATP sensors](configure-proxy.md).

### Can Azure ATP monitored domain controllers be virtualized on your IaaS solution?
Yes, you can use the Azure ATP sensor to monitor domain controllers that are in any IaaS solution.

### Can Azure ATP support multi-domain and multi-forest?
Azure Advanced Threat Protection supports multi-domain environments and multiple forests. For more information and trust requirements, see [Multi-forest support](atp-multi-forest.md).

### Can you see the overall health of the deployment?
Yes, you can view the overall health of the deployment as well as specific issues related to configuration, connectivity etc., and you are alerted as they occur with Azure ATP health alerts.

## Operation

### What kind of integration does Azure ATP have with SIEMs?
Azure ATP can be configured to send a Syslog alert, to any SIEM server using the CEF format, for health alerts and when a security alert is detected. See the [SIEM log reference](cef-format-sa.md) for more information .

### Why are certain accounts considered sensitive?
This happens when an account is a member of groups that are designated as sensitive (for example: "Domain Admins").

To understand why an account is sensitive you can review its group membership to understand which sensitive groups it belongs to (the group that it belongs to can also be sensitive due to another group, so the same process should be performed until you locate the highest level sensitive group). You can also manually [tag accounts as sensitive](sensitive-accounts.md).

### Do you have to write your own rules and create a threshold/baseline?
With Azure Advanced Threat Protection, there is no need to create rules, thresholds, or baselines and then fine-tune. Azure ATP analyzes the behaviors among users, devices, and resources, as well as their relationship to one another, and can detect suspicious activity and known attacks quickly. Three weeks after deployment, Azure ATP starts to detect behavioral suspicious activities. On the other hand, Azure ATP will start detecting known malicious attacks and security issues immediately after deployment.

### Which traffic does Azure ATP generate in the network from domain controllers, and why? 

Azure ATP generates traffic from domain controllers to computers in the organization in one of three scenarios:
1. **Network Name resolution**<br>
   Azure ATP captures traffic and events, learning and profiling users and computer activities in the network. To learn and profile activities according to computers in the organization, Azure ATP needs to resolve IPs to computer accounts. To resolve IPs to computer names Azure ATP sensors request the IP address for the computer name *behind* the IP address. <br>
 
   Requests are made using one of four methods: 
    - NTLM over RPC (TCP Port 135)
    - NetBIOS (UDP port 137)
    - RDP (TCP port 3389)
    - Query the DNS server using reverse DNS lookup of the IP address (UDP 53)
    
    After getting the computer name,  Azure ATP sensors cross check the details in Active Directory to see if there is a correlated computer object with the same computer name. If a match is found, an association is made between the IP address and the matched computer object.
2. **Lateral Movement Path (LMP)**<br>
    To build potential LMPs to sensitive users, Azure ATP requires information about the local administrators on computers. In this scenario, the Azure ATP sensor uses SAM-R (TCP 445) to query the IP address identified in the network traffic, in order to determine the local administrators of the computer. To learn more about Azure ATP and SAM-R, See [Configure SAM-R required permissions](install-atp-step8-samr.md). 

3. **Querying Active Directory using LDAP** for entity data<br>
    Azure ATP sensors query the domain controller from the domain where the entity belongs. It can be the same sensor, or another domain controller from that domain. 

|Protocol|Service|Port|Source| Direction|
|---------|---------|---------|---------|--------|
|LDAP|TCP and UDP|389|Domain controllers|Outbound|
|Secure LDAP (LDAPS)|TCP|636|Domain controllers|Outbound|
|LDAP to Global Catalog|TCP|3268|Domain controllers|Outbound|
|LDAPS to Global Catalog|TCP|3269|Domain controllers|Outbound|
|

### Why don't activities always show both the source user and computer?

Azure ATP captures activities over many different protocols. In some cases, Azure ATP doesn't receive the data of the source user in the traffic. Azure ATP attempts to correlate the session of the user to the activity, and when the attempt is successful, the source user of the activity is displayed. When user correlation attempts fail, only the source computer is displayed. 

## Troubleshooting

### What should I do if the Azure ATP sensor or standalone sensor doesn't start?
Look at the most recent error in the current error [log](troubleshooting-atp-using-logs.md) (Where Azure ATP is installed under the "Logs" folder).


## See Also
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Troubleshooting](troubleshooting-atp-known-issues.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
