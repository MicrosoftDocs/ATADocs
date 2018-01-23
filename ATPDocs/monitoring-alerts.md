---
# required metadata

title: Understanding ATP monitoring alerts | Microsoft Docs
description: Describes how you can use the ATP logs to troubleshoot issues
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: b04fb8a4-b366-4b55-9d4c-6f054fa58a90


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



The ATP Health Center lets you know when there's a problem with the ATP deployment, by raising a monitoring alert.
This article describes all the monitoring alerts for each component, listing the cause and the steps needed to resolve the problem.
## ATP Center Issues
### Center running out of disk space
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The free space on the ATP Center machine drive that is used for storing the ATP database is getting low.|This means that the hard drive has less than 200 GB of free space or that there is less than 20% free space, whichever is smaller. When ATP recognizes that the drive is running low on space, it starts to delete old data from the database. If it cannot delete old data because it still needs the data for the detection engine, you receive this alert. When you receive this alert, ATP stops keeping track of new activities.|Increase the drive size or free up space from that drive.|High|
### Failure sending mail
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|ATP Failed to send an email notification to the specified mail server.|No email messages are sent from ATP.|Verify the SMTP server configuration.|Low|

### Center overloaded
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Center is not able to handle the amount of data being transferred from the ATP Gateways. |The ATP Center stops analyzing new network traffic and events. This means that the accuracy of the detections and profiles is reduced while this monitoring alert is active.|Make sure that you provided enough resources for the ATP Center. For more details on how to properly plan for ATP Center capacity, see [ATP capacity planning](ata-capacity-planning.md). Investigate the performance of the ATP Center using [Troubleshooting ATP using the performance counters](troubleshooting-ata-using-perf-counters.md).|High|

### Failure connecting to the SIEM server using Syslog
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|ATP failed to send events to the specified SIEM.|This means the ATP Center cannot send suspicious activities and monitoring alerts to your SIEM.|Make sure that your [Syslog server settings are configured correctly](setting-syslog-email-server-settings.md).|Low|
### Center certificate is about to expire
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Center certificate will expire in less than 3 weeks.|After the certificate expires: Connectivity from ATP Gateways to ATP Center will fail. The ATP Center process will crash and all ATP functionality will stops.|[Replace the ATP Center certificate](modifying-ata-center-configuration.md)|Medium|
### ATP Center certificate expired
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Center certificate expired.|After the certificate expires: Connectivity from the ATP Gateways to the ATP Center fails. The ATP Center process crashes and all ATP functionality stops.|[Replace the ATP Center certificate](modifying-ata-center-configuration.md)|High|
## ATP Gateway issues
### Read-only user password to expire shortly
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The read-only user password, used to perform resolution of entities against Active Directory, is about to expire in less than 30 days.|If the password for this user expires, all the ATP Gateways stop running and no new data is collected.|[Change the domain connectivity password](modifying-ata-config-dcpassword.md) and then update the password in the ATP Console.|Medium|
### Read-only user password expired
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The read-only user password, used to get directory data, expired.|All the ATP Gateways stop running (or will stop running soon) and no new data is collected.|[Change the domain connectivity password](modifying-ata-config-dcpassword.md) and then update the password in the ATP Console.|High|
### Gateway certificate about to expire
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Gateway certificate will expire in less than 3 weeks.|Connectivity from the specific ATP Gateway to the ATP Center fails. No data from that ATP Gateway is sent.|The ATP Gateway certificate should have been renewed automatically. Read the ATP Gateway and ATP Center logs to understand why that Certificate did not renew automatically.|Medium|

### Gateway certificate expired
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Gateway certificate expired.|There is no connectivity from this ATP Gateway to the ATP Center. No data from that ATP Gateway is sent.|[Uninstall and reinstall the ATP Gateway](install-ata-step3.md).|High|
### Domain synchronizer not assigned
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|No domain synchronizer is assigned to any ATP Gateway. This may happen if there is no ATP Gateway configured as domain synchronizer candidate.|When the domain is not synchronized, changes to entities might cause entity information in ATP to become out of date or missing but does not affect any detection.|Make sure that at least one ATP Gateway is set as a [Domain synchronizer](install-ata-step5.md).|Low|
### All/Some of the capture network adapters on a Gateway are not available
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|All/Some of the selected capture network adapters on the ATP Gateway are disabled or disconnected.|Network traffic for some/all of the domain controllers is no longer captured by the ATP Gateway. This impacts the ability to detect suspicious activities, related to those domain controllers.|Make sure these selected capture network adapters on the ATP Gateway are enabled and connected.|Medium|
### Some domain controllers are unreachable by a Gateway
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|An ATP Gateway has limited functionality due to connectivity issues to some of the configured domain controllers.|Pass the Hash detection might be less accurate when some domain controllers can't be queried by the ATP Gateway.|Make sure the domain controllers are up and running and that this ATP Gateway can open LDAP connections to them.|Medium|
### All domain controllers are unreachable by a Gateway
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Gateway is currently offline due to connectivity issues to all the configured domain controllers.|This impacts ATA’s ability to detect suspicious activities related to domain controllers monitored by this ATP Gateway.| Make sure the domain controllers are up and running and that this ATP Gateway can open LDAP connections to them.|Medium|
### Gateway stopped communicating
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|There has been no communication from the ATP Gateway. The default time span for this alert is 5 minutes.|Network traffic is no longer captured by the network adapter on the ATP Gateway. This impacts ATA’s ability to detect suspicious activities, since network traffic will not be able to reach the ATP Center.|Check that the port used for the communication between the ATP Gateway and ATP Center service is not blocked by any routers or firewalls.|Medium|
### No traffic received from domain controller
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|No traffic was received from the domain controller via this ATP Gateway.|This might indicate that port mirroring from the domain controllers to the ATP Gateway is not configured yet or not working.|Verify that [port mirroring is configured properly on your network devices](configure-port-mirroring.md).<br></br>On the ATP Gateway capture NIC, disable these features in Advanced Settings:<br></br>Receive Segment Coalescing (IPv4)<br></br>Receive Segment Coalescing (IPv6)|Medium|
### Some forwarded events are not being analyzed
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Gateway is receiving more events than it can process.|Some forwarded events are not being analyzed, which can impact the ability to detect suspicious activities originating from domain controllers being monitored by this ATP Gateway.|Verify that only required events are forwarded to the ATP Gateway or try to forward some of the events to another ATP Gateway.|Medium|
### Some network traffic is not being analyzed
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Gateway is receiving more network traffic than it can process.|Some network traffic is not being analyzed, which can impact the ability to detect suspicious activities originating from domain controllers being monitored by this ATP Gateway.|Consider [adding additional processors and memory](ata-capacity-planning.md) as required. If this is a standalone ATP Gateway, reduce the number of domain controllers being monitored.<br></br>This can also happen if you are using domain controllers on VMware virtual machines. To avoid these alerts, you can check that the following settings are set to 0 or Disabled in the virtual machine:<br></br>- TsoEnable<br></br>- LargeSendOffload(IPv4)<br></br>- IPv4 TSO Offload<br></br>Also, consider disabling IPv4 Giant TSO Offload. For more information, consult your VMware documentation.|Medium|

### Gateway version outdated
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Center is newer than the version installed on the ATP Gateway. This is causing the ATP Gateway to stop functioning as expected.|This can impact the ability to detect suspicious activities originating from domain controllers being monitored by this ATP Gateway.|Update the ATP Gateway to the latest version automatically by enabling [automatic update](install-ata-step1.md) in the ATP Console or by downloading the latest ATP Gateway package available in the ATP Console.|High|
### Gateway service failed to start
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The ATP Gateway service failed to start for at least 30 minutes.|This can impact the ability to detect suspicious activities originating from domain controllers being monitored by this ATP Gateway.|Monitor ATP Gateway logs to [understand the root cause for ATP Gateway service failure](troubleshooting-ata-using-logs.md).|High|
## Lightweight Gateway
### Lightweight  Gateway reached a memory resource limit
|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The Lightweight ATP Gateway stopped itself and will restart automatically to protect the domain controller from a low memory condition.|The Lightweight ATP Gateway enforces memory limitations upon itself to prevent the domain controller from experiencing resource limitations. This happens when memory usage on the domain controller is high. Data from this domain controller is only partly monitored.|Increase the amount of memory (RAM) on the domain controller or add more domain controllers in this site to better distribute the load of this domain controller.|Medium|


## See Also
- [ATP prerequisites](ata-prerequisites.md)
- [ATP capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
