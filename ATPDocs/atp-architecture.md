---
# required metadata

title: Azure Advanced Threat Protection architecture | Microsoft Docs
description: Describes the architecture of Azure Advanced Threat Analytics (ATP)
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 9/25/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 90f68f2c-d421-4339-8e49-1888b84416e6

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


# Azure ATP Architecture

Azure ATP monitors your domain controllers by capturing and parsing network traffic and leveraging Windows events (directly from your domain controllers or from a SIEM server), and analyzes the data for attacks and threats. Utilizing profiling, deterministic detection, machine learning, and behavioral algorithms Azure ATP learns about your network, enables detection of anomalies and warns you of suspicious activities.

Azure Advanced Threat Protection architecture:

![Azure ATP architecture topology diagram](media/atp-architecture-topology.png)

This section describes how the flow of Azure ATP's network and event capturing works and drills down to describe the functionality of the main components: the Azure ATP portal, Azure ATP sensor, and Azure ATP cloud service. 

Installed directly on your domain controllers, the Azure ATP sensor accesses the required event logs directly from the domain controller. After these logs and the network traffic are parsed by the sensor, Azure ATP sends only the parsed information to the Azure ATP cloud service (only a percentage of the logs are sent). 

## Azure ATP Components
Azure ATP consists of the following components:

-	**Azure ATP portal** <br>
The Azure ATP portal allows you to create your Azure ATP instance, displays the data received from Azure ATP sensors and enables you to monitor, manage and investigate threats in your network environment.  

-   **Azure ATP sensor**<br>
Azure ATP sensors are installed directly on your domain controllers. The sensor directly monitors domain controller traffic, without the need for a dedicated server, or configuration of port mirroring.

-   **Azure ATP cloud service**<br>
Azure ATP cloud service runs on Azure infrastructure and is currently deployed in the US, Europe and Asia. Azure ATP cloud service is connected to Microsoft's intelligent security graph. 

## Azure ATP portal 
Use the Azure ATP portal to:
- Create your Azure ATP instance
- Integrate with other Microsoft security services 
- Manage Azure ATP sensor configuration settings 
- View data received from Azure ATP sensors
- Monitor detected suspicious activities and suspected attacks based on the attack kill chain model
- **Optional**: the portal can also be configured to send emails and events when security alerts or health issues are detected

> [!NOTE]
> - If no sensor is installed on your workspace within 60 days, the workspace may be deleted and you’ll need recreate it.

## Azure ATP sensor
The Azure ATP sensor has the following core functionality:
- Capture and inspect domain controller network traffic (local traffic of the domain controller)
- Receive Windows Events directly from the domain controllers 
- Receive RADIUS accounting information from your VPN provider
- Retrieve data about users and computers from the Active Directory domain
- Perform resolution of network entities (users, groups, and computers)
- Transfer relevant data to the Azure ATP cloud service
> [!NOTE]
> - By default, Azure ATP supports up to 100 sensors. If you want to install more, contact Azure ATP support.
 
## Azure TP Sensor features
The Azure ATP sensor reads events locally, without the need to purchase and maintain additional hardware or configure event. The Azure ATP sensor also supports Event Thread for Windows (ETW) which provides the log information for multiple detections. ETW based detections include both Suspicious Replication Request and Suspicious Domain Controller Promotion, both are potential DC Shadow attacks.
- Domain synchronizer candidate

    The domain synchronizer candidate is responsible for synchronizing all entities from a specific Active Directory domain proactively (similar to the mechanism used by the domain controllers themselves for replication). One sensor is chosen randomly, from the list of candidates, to serve as the domain synchronizer. 

    If the synchronizer is offline for more than 30 minutes, another candidate is chosen instead. If there is no domain synchronizer available for a specific domain, Azure ATP proactively synchronizes entities and their changes, however Azure ATP retrieves new entities as they are detected in the monitored traffic. 
    
    If there is no domain synchronizer available, and you search for an entity that did not have any traffic related to it, no search results are displayed.

    Azure ATP sensors are not synchronizer candidates by default.
- Resource limitations

    The Azure ATP sensor includes a monitoring component that evaluates the available compute and memory capacity on the domain controller on which it is running. The monitoring process runs every 10 seconds and dynamically updates the CPU and memory utilization quota on the Azure ATP sensor process. The monitoring process makes sure the domain controller always has at least 15% of free compute and memory resources available.

    No matter what occurs on the domain controller, the monitoring process continually frees up resources to make sure the domain controller's core functionality is never affected.

    If this causes the Azure ATP sensor to run out of resources, only partial traffic is monitored and the monitoring alert "Dropped port mirrored network traffic" appears in the Azure ATP portal Health page.

-  Windows Events

    To enhance Azure ATP detection coverage of Pass-the-Hash, Suspicious authentication failures, Modification to sensitive groups, Creation of suspicious services and Honeytoken activity types of attack,  Azure ATP needs to analyze the logs of the following Windows events: 4776,4732,4733,4728,4729,4756,4757,and 7045. These events are read automatically by Azure ATP sensors with correct [advanced audit policy settings](atp-advanced-audit-policy.md). 

## See Also
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP sizing tool](http://aka.ms/trisizingtool)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event forwarding](configure-event-forwarding.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)
