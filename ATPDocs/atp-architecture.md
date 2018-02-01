---
# required metadata

title: Azure Advanced Threat Protection architecture | Microsoft Docs
description: Describes the architecture of Microsoft Advance Threat Analytics (ATP)
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/1/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 90f68f2c-d421-4339-8e49-1888b84416e6

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*


# Azure ATP Architecture
The Azure Advanced Threat Protection architecture is detailed in this diagram:

![Azure ATP architecture topology diagram](media/ATP-architecture-topology.jpg)

Azure ATP monitors your domain controller network traffic by utilizing port mirroring to an Azure ATP Standalone Sensor using physical or virtual switches. If you deploy the Azure ATP Sensor directly on your domain controllers, it removes the requirement for port mirroring. In addition, Azure ATP can leverage Windows events (forwarded directly from your domain controllers or from a SIEM server) and analyze the data for attacks and threats.
This section describes the flow of network and event capturing and drills down to describe the functionality of the main components of ATP: the Azure ATP Standalone Sensor, Azure ATP Sensor (which has the same core functionality as the Azure ATP Standalone Sensor), and the Azure ATP cloud service.


![Azure ATP traffic flow diagram](media/ATP-traffic-flow.jpg)

## Azure ATP Components
Azure ATP consists of the following components:

-	**Azure ATP workspace management portal** <br>
The Azure ATP workspace management portal allows you to create a workspace and enable integration with other microsoft services.

-	**Azure ATP workspace portal** <br>
The Azure ATP workspace portal receives data from any ATP sensors and standalone sensors as well as monitor, manage and investigate threats in your environment.

-   **Azure ATP sensor**<br>
The Azure ATP sensor is installed directly on your domain controllers and monitors their traffic directly, without the need for a dedicated server or configuration of port mirroring. 

-   **Azure ATP standalone sensor**<br>
The Azure ATP standalone sensor is installed on a dedicated server that monitors the traffic from your domain controllers using either port mirroring or a network TAP. It is an alternative to the Azure ATP sensor.



An Azure ATP deployment can consist of a single Azure ATP cloud service connected to all Azure ATP standalone sensors, all Azure ATP sensors, or a combination of Azure ATP standalone sensors and Azure ATP sensors.


## Deployment options
You can deploy Azure ATP using the following combination of sensors:

-	**Using only Azure ATP sensors**<br>
Your Azure ATP deployment can contain only Azure ATP sensors: The Azure ATP sensors are deployed on each domain controller and no additional servers or port mirroring configuration is necessary.

-	**Using only Azure ATP standalone sensors** <br>
Your Azure ATP deployment can contain only Azure ATP standalone sensors, without any Azure ATP sensors: All the domain controllers must be configured to enable port mirroring to an Azure ATP Standalone Sensor or network TAPs must be in place.

-	**Using both Azure ATP standalone sensors and Azure ATP sensors**<br>
Your Azure ATP deployment includes both Azure ATP standalone sensors and Azure ATP sensors. The Azure ATP sensors are installed on some of your domain controllers (for example, all domain controllers in your branch sites). At the same time, other domain controllers are monitored by Azure ATP standalone sensors (for example, the larger domain controllers in your main data centers).

In all these scenarios, all the sensors send their data to the Azure ATP cloud service.

### Azure ATP workspace management portal

The Azure ATP cloud service performs the following functions:
-	Creates  and Manages Azure ATP workspaces

-	Enables integration with other Microsoft security services

### Azure ATP workspace portal

The Azure ATP workspace portal performs the following functions:

-   Manages Azure ATP Standalone Sensor and Azure ATP sensor configuration settings

-   Receives data from Azure ATP standalone sensors and Azure ATP sensors 

-   Detects suspicious activities

-   Runs Azure ATP behavioral machine learning algorithms to detect abnormal behavior

-   Runs various deterministic algorithms to detect advanced attacks based on the attack kill chain

-   Runs the Azure ATP Console

-   Optional: The Azure ATP cloud service can be configured to send emails and events when a suspicious activity is detected.

The Azure ATP cloud service receives parsed traffic from the Azure ATP Standalone Sensor and Azure ATP Sensor. It then performs profiling, runs deterministic detection, and runs machine learning and behavioral algorithms to learn about your network, enable detection of anomalies and warn you of suspicious activities.

|||
|-|-|
|Entity Receiver|Receives batches of entities from all Azure ATP sensors and Azure ATP standalone sensors.|
|Network Activity Processor|Processes all the network activities within each batch received. For example, matching between the various Kerberos steps performed from potentially different computers|
|Entity Profiler|Profiles all the Unique Entities according to the traffic and events. For example, Azure ATP updates the list of logged-on computers for each user profile.|
|Azure ATP workspace management portal|Manages your Azure ATP workspaces.|
|Azure ATP workspace portal|The Azure ATP workspace is used to configure Azure ATP and monitor suspicious activities detected by Azure ATP on your network. The Azure ATP workspace is not dependent on the Azure ATP sensor and runs even when the Azure ATP sensor service is stopped. |
|Detectors|The Detectors use machine learning algorithms and deterministic rules to find suspicious activities and abnormal user behavior in your network.|

Consider the following criteria when deciding how many Azure ATP Centers to deploy on your network:

-   One Azure ATP cloud service can monitor a single Active Directory forest. If you have more than one Active Directory forest, you need a minimum of one Azure ATP cloud service per Active Directory forest.

-    In large Active Directory deployments, a single Azure ATP cloud service might not be able to handle all the traffic of all your domain controllers. In this case, multiple Azure ATP Centers are required. The number of Azure ATP Centers should be dictated by [Azure ATP capacity planning](ata-capacity-planning.md).

## Azure ATP sensor and Azure ATP standalone sensor

The **Azure ATP sensor** and **Azure ATP sensor** both have the same core functionality:

-   Capture and inspect domain controller network traffic. This is port mirrored traffic for Azure ATP standalone sensors and local traffic of the domain controller in Azure ATP sensors. 

-   Receive Windows events from SIEM or Syslog servers, or from domain controllers using Windows Event Forwarding

-  Receive RADIUS accounting information from your VPN provider

-   Retrieve data about users and computers from the Active Directory domain

-   Perform resolution of network entities (users, groups, and computers)

-   Transfer relevant data to the Azure ATP cloud service

-   Monitor multiple domain controllers from a single Azure ATP Standalone Sensor, or monitor a single domain controller for an Azure ATP Sensor.

The Azure ATP Standalone Sensor receives network traffic and Windows Events from your network and processes it in the following main components:

|||
|-|-|
|Network Listener|The Network Listener captures network traffic and parsing the traffic. This is a CPU-heavy task, so  it is especially important to check [Azure ATP Prerequisites](ata-prerequisites.md) when planning your Azure ATP sensor or Azure ATP standalone sensor.|
|Event Listener|The Event Listener captures and parsing Windows Events forwarded from a SIEM server on your network.|
|Windows Event Log Reader|The Windows Event Log Reader reads and parsing Windows Events forwarded to the Azure ATP standalone sensor's Windows Event Log from the domain controllers.|
|Network Activity Translator | Translates parsed traffic into a logical representation of the traffic used by Azure ATP (NetworkActivity).
|Entity Resolver|The Entity Resolver takes the parsed data (network traffic and events) and resolves it data with Active Directory to find account and identity information. It is then matched with the IP addresses found in the parsed data. The Entity Resolver inspects the packet headers efficiently, to enable parsing of authentication packets for machine names, properties, and identities. The Entity Resolver combines the parsed authentication packets with the data in the actual packet.|
|Entity Sender|The Entity Sender sends the parsed and matched data to the Azure ATP cloud service.|

## Azure ATP Sensor features

The following features work differently depending on whether you are running an Azure ATP Standalone Sensor or an Azure ATP Sensor.

-	The Azure ATP Sensor can read events locally, without the need to configure event forwarding.

-	**Domain synchronizer candidate**<br>
The domain synchronizer candidate is responsible for synchronizing all entities from a specific Active Directory domain proactively (similar to the mechanism used by the domain controllers themselves for replication). One sensor is chosen randomly, from the list of candidates, to serve as the domain synchronizer. <br><br>
If the synchronizer is offline for more than 30 minutes, another candidate is chosen instead. If there is no domain synchronizer available for a specific domain, Azure ATP is able to proactively synchronize entities and their changes, however Azure ATP will reactively retrieve new entities as they are detected in the monitored traffic. 
<br>If there is no domain synchronizer available, and you search for an entity that did not have any traffic related to it, no search results are displayed.<br><br>
By default, all Azure ATP standalone sensors are synchronizer candidates.<br><br>
Because all Azure ATP sensors are more likely to be deployed in branch sites and on small domain controllers, they are not synchronizer candidates by default.


-	**Resource limitations**<br>
The Azure ATP Sensor includes a monitoring component that evaluates the available compute and memory capacity on the domain controller on which it is running. The monitoring process runs every 10 seconds and dynamically updates the CPU and memory utilization quota on the Azure ATP Sensor process to make sure that at any given point in time, the domain controller has at least 15% of free compute and memory resources.<br><br>
No matter what happens on the domain controller, this process always frees up resources to make sure the domain controller's core functionality is not affected.<br><br>
If this causes the Azure ATP Sensor to run out of resources, only partial traffic is monitored and the monitoring alert "Dropped port mirrored network traffic" appears in the Health page.

The following table provides an example of a domain controller with enough compute resource available to allow for a larger quota then is currently needed, so that all traffic is monitored:

> [!div class="mx-tableFixed"]
||||||
|-|-|-|-|-|
|Active Directory (Lsass.exe)|Azure ATP sensor (Microsoft.Tri.Gateway.exe)|Miscellaneous (other processes) |Azure ATP sensor quota|Is sensor dropping traffic?|
|30%|20%|10%|45%|No|

If Active Directory needs more computing power, the quota needed by the Azure ATP sensor is reduced. In the following example, The Azure ATP sensor needs more than the allocated quota and drops some of the traffic (monitoring only partial traffic):

> [!div class="mx-tableFixed"]
||||||
|-|-|-|-|-|
|Active Directory (Lsass.exe)|Azure ATP sensor (Microsoft.Tri.Gateway.exe)|Miscellaneous (other processes) |Azure ATP sensor quota|Is sensor dropping traffic?|
|60%|15%|10%|15%|Yes|


## Your network components
In order to work with ATP, make sure to check that the following components are set up.

### Port mirroring
If you are using Azure ATP standalone sensors, you have to set up port mirroring for the domain controllers that are monitored and set the Azure ATP Standalone Sensor as the destination using the physical or virtual switches. Another option is to use network TAPs. Azure ATP works if some but not all of your domain controllers are monitored, but detections are less effective.

While port mirroring mirrors all the domain controller network traffic to the Azure ATP Standalone Sensor, only a small percentage of that traffic is then sent, compressed, to the Azure ATP cloud service for analysis.

Your domain controllers and the Azure ATP standalone sensors can be physical or virtual, see [Configure port mirroring](configure-port-mirroring.md) for more information.


### Events
To enhance Azure ATP detection of Pass-the-Hash, Brute Force, Modification to sensitive groups and Honey Tokens, Azure ATP needs the following Windows events: 4776, 4732, 4733, 4728, 4729, 4756, 4757. These can either be read automatically by the Azure ATP Sensor or in case the Azure ATP Sensor is not deployed, it can be forwarded to the Azure ATP Standalone Sensor in one of two ways, by configuring the Azure ATP Standalone Sensor to listen for SIEM events or by [Configuring Windows Event Forwarding](#configuring-windows-event-forwarding).

-   Configuring the Azure ATP Standalone Sensor to listen for SIEM events <br>Configure your SIEM to forward specific Windows events to ATP. Azure ATP supports a number of SIEM vendors. For more information, see [Configure event collection](configure-event-collection.md).

-   Configuring Windows Event Forwarding<br>Another way Azure ATP can get your events is by configuring your domain controllers to forward Windows events 4776, 4732, 4733, 4728, 4729, 4756 and 4757 to your Azure ATP Standalone Sensor. This is especially useful if you don't have a SIEM or if your SIEM is not currently supported by ATP. For more information about Windows Event Forwarding in ATP, see [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding). This only applies to physical Azure ATP standalone sensors - not to the Azure ATP Sensor.


## See Also
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP sizing tool](http://aka.ms/trisizingtool)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the Azure ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)

