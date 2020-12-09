---
title: Microsoft Defender for Identity frequently asked questions
description: Provides a list of frequently asked questions about Microsoft Defender for Identity and the associated answers
ms.date: 10/27/2020
ms.topic: conceptual
---

# [!INCLUDE [Product long](includes/product-long.md)] frequently asked questions

This article provides a list of frequently asked questions and answers about [!INCLUDE [Product long](includes/product-long.md)] divided into the following categories:

- [What is [!INCLUDE [Product short](includes/product-short.md)]](#what-is-azure-atp)
- [Licensing and privacy](#licensing-and-privacy)
- [Deployment](#deployment)
- [Operations](#operation)
- [Troubleshooting](#troubleshooting)

<a name="what-is-azure-atp"></a>

## What is [!INCLUDE [Product short](includes/product-short.md)]?

### What can [!INCLUDE [Product short](includes/product-short.md)] detect?

[!INCLUDE [Product short](includes/product-short.md)] detects known malicious attacks and techniques, security issues, and risks against your network.
For the full list of [!INCLUDE [Product short](includes/product-short.md)] detections, see [What detections does [!INCLUDE [Product short](includes/product-short.md)] perform?](suspicious-activity-guide.md).

### What data does [!INCLUDE [Product short](includes/product-short.md)] collect?

[!INCLUDE [Product short](includes/product-short.md)] collects and stores information from your configured servers (domain controllers, member servers, etc.) in a database specific to the service for administration, tracking, and reporting purposes. Information collected includes network traffic to and from domain controllers (such as Kerberos authentication, NTLM authentication, DNS queries), security logs (such as Windows security events), Active Directory information (structure, subnets, sites), and entity information (such as names, email addresses, and phone numbers).

Microsoft uses this data to:

- Proactively identify indicators of attack (IOAs) in your organization
- Generate alerts if a possible attack was detected
- Provide your security operations with a view into entities related to threat signals from your network, enabling you to investigate and explore the presence of security threats on the network.

Microsoft does not mine your data for advertising or for any other purpose other than providing you the service.

### How many Directory Service credentials does [!INCLUDE [Product short](includes/product-short.md)] support?

[!INCLUDE [Product short](includes/product-short.md)] currently supports adding up to 10 different Directory Service credentials to support Active Directory environments with untrusted forests. If you require more accounts, open a support ticket.

### Does [!INCLUDE [Product short](includes/product-short.md)] only leverage traffic from Active Directory?

In addition to analyzing Active Directory traffic using deep packet inspection technology, [!INCLUDE [Product short](includes/product-short.md)] also collects relevant Windows Events from your domain controller and creates entity profiles based on information from Active Directory Domain Services. [!INCLUDE [Product short](includes/product-short.md)] also supports receiving RADIUS accounting of VPN logs from various vendors (Microsoft, Cisco, F5, and Checkpoint).

### Does [!INCLUDE [Product short](includes/product-short.md)] monitor only domain-joined devices?

No. [!INCLUDE [Product short](includes/product-short.md)] monitors all devices in the network performing authentication and authorization requests against Active Directory, including non-Windows and mobile devices.

### Does [!INCLUDE [Product short](includes/product-short.md)] monitor computer accounts as well as user accounts?

Yes. Since computer accounts (as well as any other entities) can be used to perform malicious activities, [!INCLUDE [Product short](includes/product-short.md)] monitors all computer accounts behavior and all other entities in the environment.

### What is the difference between Advanced Threat Analytics (ATA) and [!INCLUDE [Product short](includes/product-short.md)]?

ATA is a standalone on-premises solution with multiple components, such as the ATA Center that requires dedicated hardware on-premises.

[!INCLUDE [Product short](includes/product-short.md)] is a cloud-based security solution that leverages your on-premises Active Directory (Azure AD) signals. The solution is highly scalable and is frequently updated.

The final release of ATA is [generally available](https://support.microsoft.com/help/4568997/update-3-for-microsoft-advanced-threat-analytics-1-9). ATA will end Mainstream Support on January 12, 2021. Extended Support will continue until January 2026. For more information, read [our blog](https://techcommunity.microsoft.com/t5/microsoft-security-and/end-of-mainstream-support-for-advanced-threat-analytics-january/ba-p/1539181).

In contrast to the ATA sensor, the [!INCLUDE [Product short](includes/product-short.md)] sensor also uses data sources such as Event Tracing for Windows (ETW) enabling [!INCLUDE [Product short](includes/product-short.md)] to deliver additional detections.

[!INCLUDE [Product short](includes/product-short.md)]'s frequent updates include the following features and capabilities:

- **Support for [multi-forest environments](multi-forest.md)**: Provides organizations visibility across AD forests.

- **[Identity Security Posture Assessments](isp-overview.md)**: Identifies common misconfigurations and exploitable components, as well as, providing remediation paths to reduce the attack surface.

- **[UEBA capabilities](/cloud-app-security/tutorial-ueba)**: Insights into individual user risk through user investigation priority scoring. The score can assist SecOps in their investigations and help analysts understand unusual activities for the user and the organization.

- **Native integrations**: Integrates with Microsoft Cloud App Security and Azure AD Identity Protection to provide a hybrid view of what's taking place in both on-premises and hybrid environments.

- **Contributes to Microsoft 365 Defender**: Contributes alert and threat data to  Microsoft 365 Defender. Microsoft 365 Defender leverages the Microsoft 365 security portfolio (identities, endpoints, data, and applications) to automatically analyze cross-domain threat data, building a complete picture of each attack in a single dashboard. With this breadth and depth of clarity, defenders can focus on critical threats and hunt for sophisticated breaches, trusting that Microsoft 365 Defender's powerful automation stops attacks anywhere in the kill chain and returns the organization to a secure state.

## Licensing and privacy

### Where can I get a license for [!INCLUDE [Product long](includes/product-long.md)]?

[!INCLUDE [Product short](includes/product-short.md)] is available as part of Enterprise Mobility + Security 5 suite (EMS E5), and as a standalone license. You can acquire a license directly from the [Microsoft 365 portal](https://www.microsoft.com/cloud-platform/enterprise-mobility-security-pricing) or through the Cloud Solution Partner (CSP) licensing model.

### Does [!INCLUDE [Product short](includes/product-short.md)] need only a single license or does it require a license for every user I want to protect?

For information about [!INCLUDE [Product short](includes/product-short.md)] licensing requirements, see [[!INCLUDE [Product short](includes/product-short.md)] licensing guidance](/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-365-security-compliance-licensing-guidance#azure-advanced-threat-protection).

### Is my data isolated from other customer data?

Yes, your data is isolated through access authentication and logical segregation based on customer identifiers. Each customer can only access data collected from their own organization and generic data that Microsoft provides.

### Do I have the flexibility to select where to store my data?

No. When your [!INCLUDE [Product short](includes/product-short.md)] instance is created, it is stored automatically in the country data center closest to the geographical location of your AAD tenant. [!INCLUDE [Product short](includes/product-short.md)] data cannot be moved once your [!INCLUDE [Product short](includes/product-short.md)] instance is created to a different data center.

### How does Microsoft prevent malicious insider activities and abuse of high privilege roles?

Microsoft developers and administrators have, by design, been given sufficient privileges to carry out their assigned duties to operate and evolve the service. Microsoft deploys combinations of preventive, detective, and reactive controls including the following mechanisms to help protect against unauthorized developer and/or administrative activity:

- Tight access control to sensitive data
- Combinations of controls that greatly enhance independent detection of malicious activity
- Multiple levels of monitoring, logging, and reporting

In addition, Microsoft conducts background verification checks on certain operations personnel, and limits access to applications, systems, and network infrastructure in proportion to the level of background verification. Operations personnel follow a formal process when they are required to access a customer's account or related information in the performance of their duties.

## Deployment

### How many [!INCLUDE [Product short](includes/product-short.md)] sensors do I need?

Every domain controller in the environment should be covered by a [!INCLUDE [Product short](includes/product-short.md)] sensor or standalone sensor. For more information, see [[!INCLUDE [Product short](includes/product-short.md)] sensor sizing](capacity-planning.md#sizing).

### Does [!INCLUDE [Product short](includes/product-short.md)] work with encrypted traffic?

Network protocols with encrypted traffic (for example, AtSvc and WMI) are not decrypted, but are analyzed by the sensors.

### Does [!INCLUDE [Product short](includes/product-short.md)] work with Kerberos Armoring?

Enabling Kerberos Armoring, also known as Flexible Authentication Secure Tunneling (FAST), is supported by [!INCLUDE [Product short](includes/product-short.md)], with the exception of over-pass the hash detection, which does not work with Kerberos Armoring.

### How do I monitor a virtual domain controller using [!INCLUDE [Product short](includes/product-short.md)]?

Most virtual domain controllers can be covered by the [!INCLUDE [Product short](includes/product-short.md)] sensor, to determine whether the [!INCLUDE [Product short](includes/product-short.md)] sensor is appropriate for your environment, see [[!INCLUDE [Product short](includes/product-short.md)] Capacity Planning](capacity-planning.md).

If a virtual domain controller can't be covered by the [!INCLUDE [Product short](includes/product-short.md)] sensor, you can have either a virtual or physical [!INCLUDE [Product short](includes/product-short.md)] standalone sensor as described in [Configure port mirroring](configure-port-mirroring.md).  
The easiest way is to have a virtual [!INCLUDE [Product short](includes/product-short.md)] standalone sensor on every host where a virtual domain controller exists.  
If your virtual domain controllers move between hosts, you need to perform one of the following steps:

- When the virtual domain controller moves to another host, preconfigure the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor in that host to receive the traffic from the recently moved virtual domain controller.
- Make sure that you affiliate the virtual [!INCLUDE [Product short](includes/product-short.md)] standalone sensor with the virtual domain controller so that if it is moved, the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor moves with it.
- There are some virtual switches that can send traffic between hosts.

### How do I configure the [!INCLUDE [Product short](includes/product-short.md)] sensors to communicate with [!INCLUDE [Product short](includes/product-short.md)] cloud service when I have a proxy?

For your domain controllers to communicate with the cloud service, you must open: *.atp.azure.com port 443 in your firewall/proxy. For instructions on how to do this, see [Configure your proxy or firewall to enable communication with [!INCLUDE [Product short](includes/product-short.md)] sensors](configure-proxy.md).

### Can [!INCLUDE [Product short](includes/product-short.md)] monitored domain controllers be virtualized on your IaaS solution?

Yes, you can use the [!INCLUDE [Product short](includes/product-short.md)] sensor to monitor domain controllers that are in any IaaS solution.

### Can [!INCLUDE [Product short](includes/product-short.md)] support multi-domain and multi-forest?

[!INCLUDE [Product short](includes/product-short.md)] supports multi-domain environments and multiple forests. For more information and trust requirements, see [Multi-forest support](multi-forest.md).

### Can you see the overall health of the deployment?

Yes, you can view the overall health of the deployment as well as specific issues related to configuration, connectivity etc., and you are alerted as they occur with [!INCLUDE [Product short](includes/product-short.md)] health alerts.

## Operation

### What kind of integration does [!INCLUDE [Product short](includes/product-short.md)] have with SIEMs?

[!INCLUDE [Product short](includes/product-short.md)] can be configured to send a Syslog alert, to any SIEM server using the CEF format, for health alerts and when a security alert is detected. See the [SIEM log reference](cef-format-sa.md) for more information .

### Why are certain accounts considered sensitive?

This happens when an account is a member of groups that are designated as sensitive (for example: "Domain Admins").

To understand why an account is sensitive you can review its group membership to understand which sensitive groups it belongs to (the group that it belongs to can also be sensitive due to another group, so the same process should be performed until you locate the highest level sensitive group). You can also manually [tag accounts as sensitive](sensitive-accounts.md).

### Do you have to write your own rules and create a threshold/baseline?

With [!INCLUDE [Product short](includes/product-short.md)], there is no need to create rules, thresholds, or baselines and then fine-tune. [!INCLUDE [Product short](includes/product-short.md)] analyzes the behaviors among users, devices, and resources, as well as their relationship to one another, and can detect suspicious activity and known attacks quickly. Three weeks after deployment, [!INCLUDE [Product short](includes/product-short.md)] starts to detect behavioral suspicious activities. On the other hand, [!INCLUDE [Product short](includes/product-short.md)] will start detecting known malicious attacks and security issues immediately after deployment.

### Which traffic does [!INCLUDE [Product short](includes/product-short.md)] generate in the network from domain controllers, and why?

[!INCLUDE [Product short](includes/product-short.md)] generates traffic from domain controllers to computers in the organization in one of three scenarios:

1. **Network Name resolution**  
[!INCLUDE [Product short](includes/product-short.md)] captures traffic and events, learning and profiling users and computer activities in the network. To learn and profile activities according to computers in the organization, [!INCLUDE [Product short](includes/product-short.md)] needs to resolve IPs to computer accounts. To resolve IPs to computer names [!INCLUDE [Product short](includes/product-short.md)] sensors request the IP address for the computer name *behind* the IP address.

    Requests are made using one of four methods:
    - NTLM over RPC (TCP Port 135)
    - NetBIOS (UDP port 137)
    - RDP (TCP port 3389)
    - Query the DNS server using reverse DNS lookup of the IP address (UDP 53)

    After getting the computer name,  [!INCLUDE [Product short](includes/product-short.md)] sensors cross check the details in Active Directory to see if there is a correlated computer object with the same computer name. If a match is found, an association is made between the IP address and the matched computer object.
2. **Lateral Movement Path (LMP)**  
To build potential LMPs to sensitive users, [!INCLUDE [Product short](includes/product-short.md)] requires information about the local administrators on computers. In this scenario, the [!INCLUDE [Product short](includes/product-short.md)] sensor uses SAM-R (TCP 445) to query the IP address identified in the network traffic, in order to determine the local administrators of the computer. To learn more about [!INCLUDE [Product short](includes/product-short.md)] and SAM-R, See [Configure SAM-R required permissions](install-step8-samr.md).

3. **Querying Active Directory using LDAP** for entity data  
[!INCLUDE [Product short](includes/product-short.md)] sensors query the domain controller from the domain where the entity belongs. It can be the same sensor, or another domain controller from that domain.

|Protocol|Service|Port|Source| Direction|
|---------|---------|---------|---------|--------|
|LDAP|TCP and UDP|389|Domain controllers|Outbound|
|Secure LDAP (LDAPS)|TCP|636|Domain controllers|Outbound|
|LDAP to Global Catalog|TCP|3268|Domain controllers|Outbound|
|LDAPS to Global Catalog|TCP|3269|Domain controllers|Outbound|

### Why don't activities always show both the source user and computer?

[!INCLUDE [Product short](includes/product-short.md)] captures activities over many different protocols. In some cases, [!INCLUDE [Product short](includes/product-short.md)] doesn't receive the data of the source user in the traffic. [!INCLUDE [Product short](includes/product-short.md)] attempts to correlate the session of the user to the activity, and when the attempt is successful, the source user of the activity is displayed. When user correlation attempts fail, only the source computer is displayed.

## Troubleshooting

### What should I do if the [!INCLUDE [Product short](includes/product-short.md)] sensor or standalone sensor doesn't start?

Look at the most recent error in the current error [log](troubleshooting-using-logs.md) (Where [!INCLUDE [Product short](includes/product-short.md)] is installed under the "Logs" folder).

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md)
- [[!INCLUDE [Product short](includes/product-short.md)] capacity planning](capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Troubleshooting](troubleshooting-known-issues.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](https://aka.ms/MDIcommunity)
