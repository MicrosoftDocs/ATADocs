---
# required metadata

title: Configure Port Mirroring when deploying Azure Advanced Threat Protection
description: Describes port mirroring options and how to configure them for Azure ATP
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 02/19/2020
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 9ec7eb4c-3cad-4543-bbf0-b951d8fc8ffe

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Configure port mirroring

This article is relevant only if you deploy Azure ATP standalone sensors instead of Azure ATP sensors.

> [!NOTE]
> Azure ATP standalone sensors do not support all data source types, resulting in missed detections. For full coverage of your environment, we recommend deploying the Azure ATP sensor.

The main data source used by Azure ATP is deep packet inspection of the network traffic to and from your domain controllers. For Azure ATP to see the network traffic, you must either configure port mirroring, or use a Network TAP.

For port mirroring, configure **port mirroring** for each domain controller to be monitored, as the **source** of the network traffic. Typically, you need to work with the networking or virtualization team to configure port mirroring.
For more information, see your vendor's documentation.

Your domain controllers and Azure ATP standalone sensor can be either physical or virtual. The following are common methods for port mirroring and some considerations. For more information, see your switch or virtualization server product documentation. Your switch manufacturer might use different terminology.

**Switched Port Analyzer (SPAN)** – Copies network traffic from one or more switch ports to another switch port on the same switch. Both the Azure ATP standalone sensor and domain controllers must be connected to the same physical switch.

**Remote Switch Port Analyzer (RSPAN)**  – Allows you to monitor network traffic from source ports distributed over multiple physical switches. RSPAN copies the source traffic into a special RSPAN configured VLAN. This VLAN needs to be trunked to the other switches involved. RSPAN works at Layer 2.

**Encapsulated Remote Switch Port Analyzer (ERSPAN)** – Is a Cisco proprietary technology working at Layer 3. ERSPAN allows you to monitor traffic across switches without the need for VLAN trunks. ERSPAN uses generic routing encapsulation (GRE) to copy monitored network traffic. Azure ATP currently cannot directly receive ERSPAN traffic. For Azure ATP to work with ERSPAN traffic, a switch or router that can decapsulate the traffic needs to be configured as the destination of ERSPAN where the traffic is decapsulated. Then configure the switch or router to forward the decapsulated traffic to the Azure ATP standalone sensor using either SPAN or RSPAN.

> [!NOTE]
> If the domain controller being port mirrored is connected over a WAN link, make sure the WAN link can handle the additional load of the ERSPAN traffic.
> Azure ATP only supports traffic monitoring when the traffic reaches the NIC and the domain controller in the same manner. Azure ATP does not support traffic monitoring when the traffic is broken out to different ports.

## Supported port mirroring options

|Azure ATP standalone sensor|Domain Controller|Considerations|
|---------------|---------------------|------------------|
|Virtual|Virtual on same host|The virtual switch needs to support port mirroring.<br /><br />Moving one of the virtual machines to another host by itself may break the port mirroring.|
|Virtual|Virtual on different hosts|Make sure your virtual switch supports this scenario.|
|Virtual|Physical|Requires a dedicated network adapter otherwise Azure ATP sees all of the traffic coming in and out of the host, even the traffic it sends to the Azure ATP cloud service.|
|Physical|Virtual|Make sure your virtual switch supports this scenario - and port mirroring configuration on your physical switches based on the scenario:<br /><br />If the virtual host is on the same physical switch, you need to configure a switch level span.<br /><br />If the virtual host is on a different switch, you need to configure RSPAN or ERSPAN&#42;.|
|Physical|Physical on the same switch|Physical switch must support SPAN/Port Mirroring.|
|Physical|Physical on a different switch|Requires physical switches to support RSPAN or ERSPAN&#42;.|

&#42; ERSPAN is only supported when decapsulation is performed before the traffic is analyzed by ATP.

> [!NOTE]
> Make sure that domain controllers and the Azure ATP standalone sensor to which they connect have time synchronized to within five minutes of each other.

**If you are working with virtualization clusters:**

- For each domain controller running on the virtualization cluster in a virtual machine with the Azure ATP standalone sensor,  configure affinity between the domain controller and the Azure ATP standalone sensor. This way when the domain controller moves to another host in the cluster the Azure ATP standalone sensor follows it. This works well when there are a few domain controllers.

  > [!NOTE]
  > If your environment supports Virtual to Virtual on different hosts (RSPAN) you do not need to worry about affinity.

- To make sure the Azure ATP standalone sensor are properly sized to handle monitoring all of the DCs by themselves, try this option: Install a virtual machine on each virtualization host and install an Azure ATP standalone sensor on each host. Configure each Azure ATP standalone sensor to monitor all of the domain controllers  that run on the cluster. This way, any host the domain controllers run on is monitored.

After configuring port mirroring, validate that port mirroring is working before installing the Azure ATP standalone sensor.

## See Also

- [Configure event forwarding](configure-event-forwarding.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
