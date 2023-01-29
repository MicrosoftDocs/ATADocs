---
title: Configure port mirroring
description: Describes port mirroring options and how to configure them for Microsoft Defender for Identity
ms.date: 01/18/2023
ms.topic: how-to
---

# Configure port mirroring

This article is relevant only if you deploy Microsoft Defender for Identity standalone sensors instead of Defender for Identity sensors.

> [!NOTE]
> Defender for Identity standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the Defender for Identity sensor.

The main data source used by Defender for Identity is deep packet inspection of the network traffic to and from your domain controllers. For Defender for Identity to see the network traffic, you must either configure port mirroring, or use a Network TAP.

For port mirroring, configure **port mirroring** for each domain controller to be monitored, as the **source** of the network traffic. Typically, you need to work with the networking or virtualization team to configure port mirroring.
For more information, see your vendor's documentation.

Your domain controllers and Defender for Identity standalone sensor can be either physical or virtual. The following are common methods for port mirroring and some considerations. For more information, see your switch or virtualization server product documentation. Your switch manufacturer might use different terminology.

**Switched Port Analyzer (SPAN)** – Copies network traffic from one or more switch ports to another switch port on the same switch. Both the Defender for Identity standalone sensor and domain controllers must be connected to the same physical switch.

**Remote Switch Port Analyzer (RSPAN)**  – Allows you to monitor network traffic from source ports distributed over multiple physical switches. RSPAN copies the source traffic into a special RSPAN configured VLAN. This VLAN needs to be trunked to the other switches involved. RSPAN works at Layer 2.

**Encapsulated Remote Switch Port Analyzer (ERSPAN)** – Is a Cisco proprietary technology working at Layer 3. ERSPAN allows you to monitor traffic across switches without the need for VLAN trunks. ERSPAN uses generic routing encapsulation (GRE) to copy monitored network traffic. Defender for Identity currently cannot directly receive ERSPAN traffic. For Defender for Identity to work with ERSPAN traffic, a switch or router that can decapsulate the traffic needs to be configured as the destination of ERSPAN where the traffic is decapsulated. Then configure the switch or router to forward the decapsulated traffic to the Defender for Identity standalone sensor using either SPAN or RSPAN.

> [!NOTE]
> If the domain controller being port mirrored is connected over a WAN link, make sure the WAN link can handle the additional load of the ERSPAN traffic.
> Defender for Identity only supports traffic monitoring when the traffic reaches the NIC and the domain controller in the same manner. Defender for Identity does not support traffic monitoring when the traffic is broken out to different ports.

## Supported port mirroring options

|Defender for Identity standalone sensor|Domain Controller|Considerations|
|---------------|---------------------|------------------|
|Virtual|Virtual on same host|The virtual switch needs to support port mirroring.<br /><br />Moving one of the virtual machines to another host by itself may break the port mirroring.|
|Virtual|Virtual on different hosts|Make sure your virtual switch supports this scenario.|
|Virtual|Physical|Requires a dedicated network adapter otherwise Defender for Identity sees all of the traffic coming in and out of the host, even the traffic it sends to the Defender for Identity cloud service.|
|Physical|Virtual|Make sure your virtual switch supports this scenario - and port mirroring configuration on your physical switches based on the scenario:<br /><br />If the virtual host is on the same physical switch, you need to configure a switch level span.<br /><br />If the virtual host is on a different switch, you need to configure RSPAN or ERSPAN&#42;.|
|Physical|Physical on the same switch|Physical switch must support SPAN/Port Mirroring.|
|Physical|Physical on a different switch|Requires physical switches to support RSPAN or ERSPAN&#42;.|

&#42; ERSPAN is only supported when decapsulation is performed before the traffic is analyzed by Defender for Identity.

> [!NOTE]
> Make sure that domain controllers and the Defender for Identity standalone sensor to which they connect have time synchronized to within five minutes of each other.

**If you are working with virtualization clusters:**

- For each domain controller running on the virtualization cluster in a virtual machine with the Defender for Identity standalone sensor,  configure affinity between the domain controller and the Defender for Identity standalone sensor. This way when the domain controller moves to another host in the cluster the Defender for Identity standalone sensor follows it. This works well when there are a few domain controllers.

  > [!NOTE]
  > If your environment supports Virtual to Virtual on different hosts (RSPAN) you do not need to worry about affinity.

- To make sure the Defender for Identity standalone sensor are properly sized to handle monitoring all of the DCs by themselves, try this option: Install a virtual machine on each virtualization host and install a Defender for Identity standalone sensor on each host. Configure each Defender for Identity standalone sensor to monitor all of the domain controllers  that run on the cluster. This way, any host the domain controllers run on is monitored.

After configuring port mirroring, validate that port mirroring is working before installing the Defender for Identity standalone sensor.

## See Also

- [Configure event forwarding](configure-event-forwarding.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
