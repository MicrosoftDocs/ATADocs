---
title: Microsoft Defender for Identity architecture
description: Describes the architecture of Microsoft Defender for Identity
ms.date: 12/23/2020
ms.topic: overview
---

# Microsoft Defender for Identity architecture

[!INCLUDE [Product long](includes/product-long.md)] monitors your domain controllers by capturing and parsing network traffic and leveraging Windows events directly from your domain controllers, then analyzes the data for attacks and threats. Utilizing profiling, deterministic detection, machine learning, and behavioral algorithms [!INCLUDE [Product short](includes/product-short.md)] learns about your network, enables detection of anomalies, and warns you of suspicious activities.

[!INCLUDE [Product short](includes/product-short.md)] architecture:

![[!INCLUDE [Product short.](includes/product-short.md)] architecture topology diagram](media/architecture-topology.png)

This section describes how the flow of [!INCLUDE [Product short](includes/product-short.md)]'s network and event capturing works, and drills down to describe the functionality of the main components: the Microsoft 365 Defender portal, [!INCLUDE [Product short](includes/product-short.md)] sensor, and [!INCLUDE [Product short](includes/product-short.md)] cloud service.

Installed directly on your domain controller or AD FS servers, the [!INCLUDE [Product short](includes/product-short.md)] sensor accesses the event logs it requires directly from the servers. After the logs and network traffic are parsed by the sensor, [!INCLUDE [Product short](includes/product-short.md)] sends only the parsed information to the [!INCLUDE [Product short](includes/product-short.md)] cloud service (only a percentage of the logs are sent).

## Defender for Identity components

[!INCLUDE [Product short](includes/product-short.md)] consists of the following components:

- **Microsoft 365 Defender portal**  
The Microsoft 365 Defender portal creates your [!INCLUDE [Product short](includes/product-short.md)] instance, displays the data received from [!INCLUDE [Product short](includes/product-short.md)] sensors, and enables you to monitor, manage, and investigate threats in your network environment.

- **[!INCLUDE [Product short](includes/product-short.md)] sensor**  
[!INCLUDE [Product short](includes/product-short.md)] sensors can be directly installed on the following servers:
  - **Domain controllers**: The sensor directly monitors domain controller traffic, without the need for a dedicated server, or configuration of port mirroring.
  - **AD FS**: The sensor directly monitors network traffic and authentication events.
- **[!INCLUDE [Product short](includes/product-short.md)] cloud service**  
[!INCLUDE [Product short](includes/product-short.md)] cloud service runs on Azure infrastructure and is currently deployed in the US, Europe, and Asia. [!INCLUDE [Product short](includes/product-short.md)] cloud service is connected to Microsoft's intelligent security graph.

## Microsoft 365 Defender portal

Use the Microsoft 365 Defender portal to:

- Create your [!INCLUDE [Product short](includes/product-short.md)] instance
- Integrate with other Microsoft security services
- Manage [!INCLUDE [Product short](includes/product-short.md)] sensor configuration settings
- View data received from [!INCLUDE [Product short](includes/product-short.md)] sensors
- Monitor detected suspicious activities and suspected attacks based on the attack kill chain model
- **Optional**: the portal can also be configured to send emails and events when security alerts or health issues are detected

> [!NOTE]
> If no sensor is installed on your [!INCLUDE [Product short](includes/product-short.md)] instance within 60 days, the instance may be deleted and you'll need to recreate it.

## Defender for Identity sensor

The [!INCLUDE [Product short](includes/product-short.md)] sensor has the following core functionality:

- Capture and inspect domain controller network traffic (local traffic of the domain controller)
- Receive Windows Events directly from the domain controllers
- Receive RADIUS accounting information from your VPN provider
- Retrieve data about users and computers from the Active Directory domain
- Perform resolution of network entities (users, groups, and computers)
- Transfer relevant data to the [!INCLUDE [Product short](includes/product-short.md)] cloud service

## Defender for Identity sensor features

[!INCLUDE [Product short](includes/product-short.md)] sensor reads events locally, without the need to purchase and maintain additional hardware or configurations. The [!INCLUDE [Product short](includes/product-short.md)] sensor also supports Event Tracing for Windows (ETW) which provides the log information for multiple detections. ETW-based detections include Suspected DCShadow attacks attempted using domain controller replication requests and domain controller promotion.

### Domain synchronizer process

The domain synchronizer process is responsible for synchronizing all entities from a specific Active Directory domain proactively (similar to the mechanism used by the domain controllers themselves for replication). One sensor is automatically chosen at random from all of your eligible sensors to serve as the domain synchronizer.

If the domain synchronizer is offline for more than 30 minutes, another sensor is automatically chosen instead.

### Resource limitations

The [!INCLUDE [Product short](includes/product-short.md)] sensor includes a monitoring component that evaluates the available compute and memory capacity on the domain controller on which it's running. The monitoring process runs every 10 seconds and dynamically updates the CPU and memory utilization quota on the [!INCLUDE [Product short](includes/product-short.md)] sensor process. The monitoring process makes sure the domain controller always has at least 15% of free compute and memory resources available.

No matter what occurs on the domain controller, the monitoring process continually frees up resources to make sure the domain controller's core functionality is never affected.

If the monitoring process causes the [!INCLUDE [Product short](includes/product-short.md)] sensor to run out of resources, only partial traffic is monitored and the health alert "Dropped port mirrored network traffic" appears in the [!INCLUDE [Product short](includes/product-short.md)] sensor page.

### Windows Events

To enhance [!INCLUDE [Product short](includes/product-short.md)] detection coverage related to NTLM authentications, modifications to sensitive groups and creation of suspicious services, [!INCLUDE [Product short](includes/product-short.md)] needs to analyze the logs of the [Windows Events listed here](configure-windows-event-collection.md#relevant-windows-events). These events are read automatically by [!INCLUDE [Product short](includes/product-short.md)] sensors with correct [advanced audit policy settings](configure-windows-event-collection.md). To [make sure Windows Event 8004 is audited](configure-windows-event-collection.md#event-id-8004) as needed by the service, review your [NTLM audit settings](/archive/blogs/askds/ntlm-blocking-and-you-application-analysis-and-auditing-methodologies-in-windows-7).

## Next steps

- [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md)
- [[!INCLUDE [Product short](includes/product-short.md)] capacity planning](capacity-planning.md)
- [[!INCLUDE [Product short](includes/product-short.md)] sizing tool](capacity-planning.md#use-the-sizing-tool)
- [Configure event forwarding](configure-event-forwarding.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
