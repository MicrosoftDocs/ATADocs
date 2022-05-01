---
title: Understanding Microsoft Defender for Identity health alerts
description: This article describes all the health alerts for each component, listing the cause and the steps needed to resolve the problem
ms.date: 10/26/2020
ms.topic: how-to
---

# Understanding Microsoft Defender for Identity sensor health alerts

> [!NOTE]
> The experience described in this page can also be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender. The supporting documents for the new experience can be found [here](/microsoft-365/security/defender-identity/sensor-health). For more information about Microsoft Defender for Identity and when other features will be available in Microsoft 365 Defender, see [Microsoft Defender for Identity in Microsoft 365 Defender](defender-for-identity-in-microsoft-365-defender.md).

The [!INCLUDE [Product long](includes/product-long.md)] Health Center lets you know when there's a problem with your [!INCLUDE [Product short](includes/product-short.md)] instance, by raising a health alert. This article describes all the health alerts for each component, listing the cause and the steps needed to resolve the problem.

## All domain controllers are unreachable by a sensor

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The [!INCLUDE [Product short](includes/product-short.md)] sensor is currently offline due to connectivity issues to all the configured domain controllers.|This impacts [!INCLUDE [Product short](includes/product-short.md)]'s ability to detect suspicious activities related to domain controllers monitored by this [!INCLUDE [Product short](includes/product-short.md)] sensor.| Make sure the domain controllers are up and running and that this [!INCLUDE [Product short](includes/product-short.md)] sensor can open LDAP connections to them. In addition, in **Settings** make sure to configure a directory service account for every deployed forest.|Medium|

## All/Some of the capture network adapters on a sensor are not available

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|All/Some of the selected capture network adapters on the [!INCLUDE [Product short](includes/product-short.md)] sensor are disabled or disconnected.|Network traffic for some/all of the domain controllers is no longer captured by the [!INCLUDE [Product short](includes/product-short.md)] sensor. This impacts the ability to detect suspicious activities, related to those domain controllers.|Make sure these selected capture network adapters on the [!INCLUDE [Product short](includes/product-short.md)] sensor are enabled and connected.|Medium|

## Directory services user credentials are incorrect

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The credentials for the directory services user account are incorrect.|This impacts sensors' ability to detect activities using LDAP queries against domain controllers.|- For a **standard** AD accounts: Verify that the username, password, and domain in the **Directory services** configuration page are correct.<br>- For **group Managed Service Accounts:** Verify that the username and domain in the **Directory Services** configuration page are correct. Also check all the other **gMSA account** prerequisites described on the [Connect to your Active Directory Forest](install-step2.md#prerequisites) page.|Medium|

## Low success rate of active name resolution

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The listed [!INCLUDE [Product short](includes/product-short.md)] sensors are failing to resolve IP addresses to device names more than 90% of the time using the following methods:<br />- NTLM over RPC<br />- NetBIOS<br />- Reverse DNS|This impacts [!INCLUDE [Product short](includes/product-short.md)]'s detections capabilities and might increase the number of false positive alarms.|- For NTLM over RPC: Check that port 135 is open for inbound communication from [!INCLUDE [Product short](includes/product-short.md)] sensors on all computers in the environment.<br />- For reverse DNS: Check that the sensors can reach the DNS server and that Reverse Lookup Zones are enabled.<br />- For NetBIOS: Check that port 137 is open for inbound communication from [!INCLUDE [Product short](includes/product-short.md)] sensors on all computers in the environment.<br />Additionally, make sure that the network configuration (such as firewalls) isn't preventing communication to the relevant ports.|Low|

## No traffic received from domain controller

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|No traffic was received from the domain controller via this [!INCLUDE [Product short](includes/product-short.md)] sensor.|This might indicate that port mirroring from the domain controllers to the [!INCLUDE [Product short](includes/product-short.md)] sensor isn't configured yet or not working.|Verify that [port mirroring is configured properly on your network devices](configure-port-mirroring.md).<br></br>On the [!INCLUDE [Product short](includes/product-short.md)] sensor capture NIC, disable these features in Advanced Settings:<br></br>Receive Segment Coalescing (IPv4)<br></br>Receive Segment Coalescing (IPv6)|Medium|

## Read-only user password to expire shortly

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The read-only user password, used to perform resolution of entities against Active Directory, is about to expire in less than 30 days.|If the password for this user expires, all the [!INCLUDE [Product short](includes/product-short.md)] sensors stop running and no new data is collected.|[Change the domain connectivity password](modifying-config-dcpassword.md) and then update the password in the [!INCLUDE [Product short](includes/product-short.md)] portal.|Medium|

## Read-only user password expired

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The read-only user password, used to get directory data, expired.|All the [!INCLUDE [Product short](includes/product-short.md)] sensors stop running (or will stop running soon) and no new data is collected.|[Change the domain connectivity password](modifying-config-dcpassword.md) and then update the password in the [!INCLUDE [Product short](includes/product-short.md)] portal.|High|

## Sensor outdated

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|A [!INCLUDE [Product short](includes/product-short.md)] sensor is outdated.|A [!INCLUDE [Product short](includes/product-short.md)] sensor is running a version that can't communicate with the [!INCLUDE [Product short](includes/product-short.md)] cloud infrastructure.|Manually update the sensor and check to see why the sensor isn't automatically updating. If this doesn't work, download the latest sensor installation package and uninstall and reinstall the sensor. For more information, see [Installing the [!INCLUDE [Product short](includes/product-short.md)] sensor](install-step4.md).|Medium|

## Sensor reached a memory resource limit

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The [!INCLUDE [Product short](includes/product-short.md)] sensor stopped itself and restarts automatically to protect the domain controller from a low memory condition.|The [!INCLUDE [Product short](includes/product-short.md)] sensor enforces memory limitations upon itself to prevent the domain controller from experiencing resource limitations. This happens when memory usage on the domain controller is high. Data from this domain controller is only partly monitored.|Increase the amount of memory (RAM) on the domain controller or add more domain controllers in this site to better distribute the load of this domain controller.|Medium|

## Sensor service failed to start

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The [!INCLUDE [Product short](includes/product-short.md)] sensor service failed to start for at least 30 minutes.|This can impact the ability to detect suspicious activities originating from domain controllers being monitored by this [!INCLUDE [Product short](includes/product-short.md)] sensor.|Monitor [!INCLUDE [Product short](includes/product-short.md)] sensor logs to understand the root cause for [!INCLUDE [Product short](includes/product-short.md)] sensor service failure.|High|

## Sensor stopped communicating

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|There has been no communication from the [!INCLUDE [Product short](includes/product-short.md)] sensor. The default time span for this alert is 5 minutes.|Network traffic is no longer captured by the network adapter on the [!INCLUDE [Product short](includes/product-short.md)] sensor. This impacts ATA's ability to detect suspicious activities, since network traffic won't be able to reach the [!INCLUDE [Product short](includes/product-short.md)] cloud service.|Check that the port used for the communication between the [!INCLUDE [Product short](includes/product-short.md)] sensor and [!INCLUDE [Product short](includes/product-short.md)] cloud service is not blocked by any routers or firewalls.|Medium|

## Some domain controllers are unreachable by a sensor

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|A [!INCLUDE [Product short](includes/product-short.md)] sensor has limited functionality due to connectivity issues to some of the configured domain controllers.|Pass the Hash detection might be less accurate when some domain controllers can't be queried by the [!INCLUDE [Product short](includes/product-short.md)] sensor.|Make sure the domain controllers are up and running and that this [!INCLUDE [Product short](includes/product-short.md)] sensor can open LDAP connections to them.|Medium|

## Some Windows events are not being analyzed

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The [!INCLUDE [Product short](includes/product-short.md)] sensor is receiving more events than it can process.|Some Windows events aren't being analyzed, which can impact the ability to detect suspicious activities originating from domain controllers being monitored by this [!INCLUDE [Product short](includes/product-short.md)] sensor.|Verify that only required events are forwarded to the [!INCLUDE [Product short](includes/product-short.md)] sensor or try to forward some of the events to another [!INCLUDE [Product short](includes/product-short.md)] sensor.|Medium|

## Some network traffic could not be analyzed

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The [!INCLUDE [Product short](includes/product-short.md)] sensor is receiving more network traffic than it can process.|Some network traffic couldn't be analyzed, which can impact the ability to detect suspicious activities originating from domain controllers being monitored by this [!INCLUDE [Product short](includes/product-short.md)] sensor.|Consider [adding additional processors and memory](capacity-planning.md) as required. If this is a standalone [!INCLUDE [Product short](includes/product-short.md)] sensor, reduce the number of domain controllers being monitored.<br></br>This can also happen if you're using domain controllers on VMware virtual machines. To avoid these alerts, you can check that the following settings are set to 0 or Disabled in the virtual machine:<br></br>- TsoEnable<br></br>- LargeSendOffload(IPv4)<br></br>- IPv4 TSO Offload<br></br>Also, consider disabling IPv4 Giant TSO Offload. For more information, see your VMware documentation.|Medium|

## Some ETW events are not being analyzed

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The [!INCLUDE [Product short](includes/product-short.md)] sensor is receiving more Event Tracing for Windows (ETW) events than it can process.|Some Event Tracing for Windows (ETW) events aren't being analyzed, which can impact the ability to detect suspicious activities originating from domain controllers being monitored by this [!INCLUDE [Product short](includes/product-short.md)] sensor.|Make sure the sensor machine is sized correctly according to the [sizing tool](capacity-planning.md). If it is, contact support. |Medium|

## Sensor with Windows Server 2008 R2: Will be unsupported soon

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The [!INCLUDE [Product short](includes/product-short.md)] sensor is running on Windows 2008 R2 which will be unsupported soon.|Starting June 15th 2022, Microsoft will no longer support the [!INCLUDE [Product short](includes/product-short.md)] sensor on devices running Windows Server 2008 R2. More details can be fount at: https://aka.ms/mdi/2008r2 |Upgrade the Operating System on this Domain Controller to at least Windows Server 2012.|Medium (Starting June 1st, 2022 the severity of this halth alert will be High)|


## Sensor with Windows Server 2008 R2: Unsupported

|Alert|Description|Resolution|Severity|
|----|----|----|----|
|The [!INCLUDE [Product short](includes/product-short.md)] sensor is running on Windows 2008 R2 which is unsupported.|Starting June 15th 2022, Microsoft will no longer support the [!INCLUDE [Product short](includes/product-short.md)] sensor on devices running Windows Server 2008 R2. More details can be fount at: https://aka.ms/mdi/2008r2 |Upgrade the Operating System on this Domain Controller to at least Windows Server 2012.|High|

<!--
## Windows events missing from domain controller audit policy

|Alert|Description|Resolution|Severity|
|----|----|----|----|
| Windows events missing from domain controller audit policy|For the correct events to be audited and included in the Windows Event Log, your domain controllers require accurate Advanced Audit Policy settings. Incorrect Advanced Audit Policy settings leave critical events out of your logs, and result in incomplete [!INCLUDE [Product short](includes/product-short.md)] coverage.|Review your [Advanced Audit policy](configure-windows-event-collection.md) and modify as needed. | Medium|
-->

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md)
- [[!INCLUDE [Product short](includes/product-short.md)] capacity planning](capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
