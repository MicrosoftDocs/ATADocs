---
# required metadata

title: Understanding Azure ATP health alerts
description: Describes how you can use the Azure ATP logs to troubleshoot issues
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 02/19/2020
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: d0551e91-3b21-47d5-ad9d-3362df6d47c0


# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Understanding Azure ATP sensor health alerts

The Azure ATP Health Center lets you know when there's a problem with your Azure ATP instance, by raising a health alert. This article describes all the health alerts for each component, listing the cause and the steps needed to resolve the problem.

## All domain controllers are unreachable by a sensor

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The Azure ATP sensor is currently offline due to connectivity issues to all the configured domain controllers.|This impacts Azure ATP’s ability to detect suspicious activities related to domain controllers monitored by this Azure ATP sensor.| Make sure the domain controllers are up and running and that this Azure ATP sensor can open LDAP connections to them. In addition, in **Settings** make sure to configure a directory service account for every deployed forest.|Medium|

## All/Some of the capture network adapters on a sensor are not available

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|All/Some of the selected capture network adapters on the Azure ATP sensor are disabled or disconnected.|Network traffic for some/all of the domain controllers is no longer captured by the Azure ATP sensor. This impacts the ability to detect suspicious activities, related to those domain controllers.|Make sure these selected capture network adapters on the Azure ATP sensor are enabled and connected.|Medium|

## Directory services user credentials are incorrect

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The credentials for the directory services user account are incorrect.|This impacts sensors' ability to detect activities using LDAP queries against domain controllers.|- For a **standard** AD accounts: Verify that the username, password, and domain in the **Directory services** configuration page are correct.<br>- For **group Managed Service Accounts:** Verify that the username and domain in the **Directory Services** configuration page are correct. Also check all the other **gMSA account** prerequisites described on the [Connect to your Active Directory Forest](install-atp-step2.md#prerequisites) page.|Medium|

## No traffic received from domain controller

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|No traffic was received from the domain controller via this Azure ATP sensor.|This might indicate that port mirroring from the domain controllers to the Azure ATP sensor is not configured yet or not working.|Verify that [port mirroring is configured properly on your network devices](configure-port-mirroring.md).<br></br>On the Azure ATP sensor capture NIC, disable these features in Advanced Settings:<br></br>Receive Segment Coalescing (IPv4)<br></br>Receive Segment Coalescing (IPv6)|Medium|

## Read-only user password to expire shortly

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The read-only user password, used to perform resolution of entities against Active Directory, is about to expire in less than 30 days.|If the password for this user expires, all the Azure ATP sensors stop running and no new data is collected.|[Change the domain connectivity password](modifying-atp-config-dcpassword.md) and then update the password in the Azure ATP portal.|Medium|

## Read-only user password expired

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The read-only user password, used to get directory data, expired.|All the Azure ATP sensors stop running (or will stop running soon) and no new data is collected.|[Change the domain connectivity password](modifying-atp-config-dcpassword.md) and then update the password in the Azure ATP portal.|High|

## Sensor outdated

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|An Azure ATP sensor is outdated.|An Azure ATP sensor is running a version that cannot communicate with the Azure ATP cloud infrastructure.|Manually update the sensor and check to see why the sensor isn't automatically updating. If this doesn't work, download the latest sensor installation package and uninstall and reinstall the sensor. For more information, see [Installing the Azure ATP sensor](install-atp-step4.md).|Medium|

## Sensor reached a memory resource limit

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The Azure ATP sensor stopped itself and restarts automatically to protect the domain controller from a low memory condition.|The Azure ATP sensor enforces memory limitations upon itself to prevent the domain controller from experiencing resource limitations. This happens when memory usage on the domain controller is high. Data from this domain controller is only partly monitored.|Increase the amount of memory (RAM) on the domain controller or add more domain controllers in this site to better distribute the load of this domain controller.|Medium|

## Sensor service failed to start

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The Azure ATP sensor service failed to start for at least 30 minutes.|This can impact the ability to detect suspicious activities originating from domain controllers being monitored by this Azure ATP sensor.|Monitor Azure ATP sensor logs to understand the root cause for Azure ATP sensor service failure.|High|

## Sensor stopped communicating

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|There has been no communication from the Azure ATP sensor. The default time span for this alert is 5 minutes.|Network traffic is no longer captured by the network adapter on the Azure ATP sensor. This impacts ATA’s ability to detect suspicious activities, since network traffic will not be able to reach the Azure ATP cloud service.|Check that the port used for the communication between the Azure ATP sensor and Azure ATP cloud service is not blocked by any routers or firewalls.|Medium|

## Some domain controllers are unreachable by a sensor

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|An Azure ATP sensor has limited functionality due to connectivity issues to some of the configured domain controllers.|Pass the Hash detection might be less accurate when some domain controllers can't be queried by the Azure ATP sensor.|Make sure the domain controllers are up and running and that this Azure ATP sensor can open LDAP connections to them.|Medium|

## Some forwarded events are not being analyzed

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The Azure ATP sensor is receiving more events than it can process.|Some forwarded events are not being analyzed, which can impact the ability to detect suspicious activities originating from domain controllers being monitored by this Azure ATP sensor.|Verify that only required events are forwarded to the Azure ATP sensor or try to forward some of the events to another Azure ATP sensor.|Medium|

## Some network traffic is not being analyzed

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The Azure ATP sensor is receiving more network traffic than it can process.|Some network traffic is not being analyzed, which can impact the ability to detect suspicious activities originating from domain controllers being monitored by this Azure ATP sensor.|Consider [adding additional processors and memory](atp-capacity-planning.md) as required. If this is a standalone Azure ATP sensor, reduce the number of domain controllers being monitored.<br></br>This can also happen if you are using domain controllers on VMware virtual machines. To avoid these alerts, you can check that the following settings are set to 0 or Disabled in the virtual machine:<br></br>- TsoEnable<br></br>- LargeSendOffload(IPv4)<br></br>- IPv4 TSO Offload<br></br>Also, consider disabling IPv4 Giant TSO Offload. For more information, see your VMware documentation.|Medium|

## Windows events missing from domain controller audit policy
|Alert|Description|Resolution|Severity|
|----|----|----|----|
| Windows events missing from domain controller audit policy|For the correct events to be audited and included in the Windows Event Log, your domain controllers require accurate Advanced Audit Policy settings. Incorrect Advanced Audit Policy settings leave critical events out of your logs, and result in incomplete Azure ATP coverage.|Review your [Advanced Audit policy](atp-advanced-audit-policy.md) and modify as needed. | Medium|



## See Also

- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
