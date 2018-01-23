---
# required metadata

title: Azure Threat Protection architecture | Microsoft Docs
description: Describes the architecture of Microsoft Advance Threat Analytics (ATP)
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 892b16d2-58a6-49f9-8693-1e5f69d8299c

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




# ATP Architecture
The Azure Threat Protection architecture is detailed in this diagram:

![ATP architecture topology diagram](media/ATP-architecture-topology.jpg)

ATP monitors your domain controller network traffic by utilizing port mirroring to an ATP Gateway using physical or virtual switches. If you deploy the ATP Lightweight Gateway directly on your domain controllers, it removes the requirement for port mirroring. In addition, ATP can leverage Windows events (forwarded directly from your domain controllers or from a SIEM server) and analyze the data for attacks and threats.
This section describes the flow of network and event capturing and drills down to describe the functionality of the main components of ATP: the ATP Gateway, ATP Lightweight Gateway (which has the same core functionality as the ATP Gateway), and the ATP Center.


![ATP traffic flow diagram](media/ATP-traffic-flow.jpg)

## ATP Components
ATP consists of the following components:

-   **ATP Center** <br>
The ATP Center receives data from any ATP Gateways and/or ATP Lightweight Gateways you deploy.
-   **ATP Gateway**<br>
The ATP Gateway is installed on a dedicated server that monitors the traffic from your domain controllers using either port mirroring or a network TAP.
-   **ATP Lightweight Gateway**<br>
The ATP Lightweight Gateway is installed directly on your domain controllers and monitors their traffic directly, without the need for a dedicated server or configuration of port mirroring. It is an alternative to the ATP Gateway.

An ATP deployment can consist of a single ATP Center connected to all ATP Gateways, all ATP Lightweight Gateways, or a combination of ATP Gateways and ATP Lightweight Gateways.


## Deployment options
You can deploy ATP using the following combination of gateways:

-	**Using only ATP Gateways** <br>
Your ATP deployment can contain only ATP Gateways, without any ATP Lightweight Gateways: All the domain controllers must be configured to enable port mirroring to an ATP Gateway or network TAPs must be in place.
-	**Using only ATP Lightweight Gateways**<br>
Your ATP deployment can contain only ATP Lightweight Gateways: The ATP Lightweight Gateways are deployed on each domain controller and no additional servers or port mirroring configuration is necessary.
-	**Using both ATP Gateways and ATP Lightweight Gateways**<br>
Your ATP deployment includes both ATP Gateways and ATP Lightweight Gateways. The ATP Lightweight Gateways are installed on some of your domain controllers (for example, all domain controllers in your branch sites). At the same time, other domain controllers are monitored by ATP Gateways (for example, the larger domain controllers in your main data centers).

In all these scenarios, all the gateways send their data to the ATP Center.




## ATP Center
The **ATP Center** performs the following functions:

-   Manages ATP Gateway and ATP Lightweight Gateway configuration settings

-   Receives data from ATP Gateways and ATP Lightweight Gateways 

-   Detects suspicious activities

-   Runs ATP behavioral machine learning algorithms to detect abnormal behavior

-   Runs various deterministic algorithms to detect advanced attacks based on the attack kill chain

-   Runs the ATP Console

-   Optional: The ATP Center can be configured to send emails and events when a suspicious activity is detected.

The ATP Center receives parsed traffic from the ATP Gateway and ATP Lightweight Gateway. It then performs profiling, runs deterministic detection, and runs machine learning and behavioral algorithms to learn about your network, enable detection of anomalies and warn you of suspicious activities.

|||
|-|-|
|Entity Receiver|Receives batches of entities from all ATP Gateways and ATP Lightweight Gateways.|
|Network Activity Processor|Processes all the network activities within each batch received. For example, matching between the various Kerberos steps performed from potentially different computers|
|Entity Profiler|Profiles all the Unique Entities according to the traffic and events. For example, ATP updates the list of logged-on computers for each user profile.|
|Center Database|Manages the writing process of the Network Activities and events into the database. |
|Database|ATP utilizes MongoDB for purposes of storing all the data in the system:<br /><br />-   Network activities<br />-   Event activities<br />-   Unique entities<br />-   Suspicious activities<br />-   ATP configuration|
|Detectors|The Detectors use machine learning algorithms and deterministic rules to find suspicious activities and abnormal user behavior in your network.|
|ATP Console|The ATP Console is for configuring ATP and monitoring suspicious activities detected by ATP on your network. The ATP Console is not dependent on the ATP Center service and runs even when the service is stopped, as long as it can communicate with the database.|
Consider the following criteria when deciding how many ATP Centers to deploy on your network:

-   One ATP Center can monitor a single Active Directory forest. If you have more than one Active Directory forest, you need a minimum of one ATP Center per Active Directory forest.

-    In large Active Directory deployments, a single ATP Center might not be able to handle all the traffic of all your domain controllers. In this case, multiple ATP Centers are required. The number of ATP Centers should be dictated by [ATP capacity planning](ata-capacity-planning.md).

## ATP Gateway and ATP Lightweight Gateway

### Gateway core functionality
The **ATP Gateway** and **ATP Lightweight Gateway** both have the same core functionality:

-   Capture and inspect domain controller network traffic. This is port mirrored traffic for ATP Gateways and local traffic of the domain controller in ATP Lightweight Gateways. 

-   Receive Windows events from SIEM or Syslog servers, or from domain controllers using Windows Event Forwarding

-   Retrieve data about users and computers from the Active Directory domain

-   Perform resolution of network entities (users, groups, and computers)

-   Transfer relevant data to the ATP Center

-   Monitor multiple domain controllers from a single ATP Gateway, or monitor a single domain controller for an ATP Lightweight Gateway.

The ATP Gateway receives network traffic and Windows Events from your network and processes it in the following main components:

|||
|-|-|
|Network Listener|The Network Listener captures network traffic and parsing the traffic. This is a CPU-heavy task, so  it is especially important to check [ATP Prerequisites](ata-prerequisites.md) when planning your ATP Gateway or ATP Lightweight Gateway.|
|Event Listener|The Event Listener captures and parsing Windows Events forwarded from a SIEM server on your network.|
|Windows Event Log Reader|The Windows Event Log Reader reads and parsing Windows Events forwarded to the ATP Gateway's Windows Event Log from the domain controllers.|
|Network Activity Translator | Translates parsed traffic into a logical representation of the traffic used by ATP (NetworkActivity).
|Entity Resolver|The Entity Resolver takes the parsed data (network traffic and events) and resolves it data with Active Directory to find account and identity information. It is then matched with the IP addresses found in the parsed data. The Entity Resolver inspects the packet headers efficiently, to enable parsing of authentication packets for machine names, properties, and identities. The Entity Resolver combines the parsed authentication packets with the data in the actual packet.|
|Entity Sender|The Entity Sender sends the parsed and matched data to the ATP Center.|

## ATP Lightweight Gateway features

The following features work differently depending on whether you are running an ATP Gateway or an ATP Lightweight Gateway.

-	The ATP Lightweight Gateway can read events locally, without the need to configure event forwarding.

-	**Domain synchronizer candidate**<br>
The domain synchronizer gateway is responsible for synchronizing all entities from a specific Active Directory domain proactively (similar to the mechanism used by the domain controllers themselves for replication). One gateway is chosen randomly, from the list of candidates, to serve as the domain synchronizer. <br><br>
If the synchronizer is offline for more than 30 minutes, another candidate is chosen instead. If there is no domain synchronizer available for a specific domain, ATP is able to proactively synchronize entities and their changes, however ATP will reactively retrieve new entities as they are detected in the monitored traffic. 
<br>If there is no domain synchronizer available, and you search for an entity that did not have any traffic related to it, no search results are displayed.<br><br>
By default, all ATP Gateways are synchronizer candidates.<br><br>
Because all ATP Lightweight Gateways are more likely to be deployed in branch sites and on small domain controllers, they are not synchronizer candidates by default.


-	**Resource limitations**<br>
The ATP Lightweight Gateway includes a monitoring component that evaluates the available compute and memory capacity on the domain controller on which it is running. The monitoring process runs every 10 seconds and dynamically updates the CPU and memory utilization quota on the ATP Lightweight Gateway process to make sure that at any given point in time, the domain controller has at least 15% of free compute and memory resources.<br><br>
No matter what happens on the domain controller, this process always frees up resources to make sure the domain controller's core functionality is not affected.<br><br>
If this causes the ATP Lightweight Gateway to run out of resources, only partial traffic is monitored and the monitoring alert "Dropped port mirrored network traffic" appears in the Health page.

The following table provides an example of a domain controller with enough compute resource available to allow for a larger quota then is currently needed, so that all traffic is monitored:

> [!div class="mx-tableFixed"]
||||||
|-|-|-|-|-|
|Active Directory (Lsass.exe)|ATP Lightweight Gateway (Microsoft.Tri.Gateway.exe)|Miscellaneous (other processes) |ATP Lightweight Gateway Quota|Gateway dropping|
|30%|20%|10%|45%|No|

If Active Directory needs more compute, the quota needed by the ATP Lightweight Gateway is reduced. In the following example, The ATP Lightweight Gateway needs more than the allocated quota and drops some of the traffic (monitoring only partial traffic):

> [!div class="mx-tableFixed"]
||||||
|-|-|-|-|-|
|Active Directory (Lsass.exe)|ATP Lightweight Gateway (Microsoft.Tri.Gateway.exe)|Miscellaneous (other processes) |ATP Lightweight Gateway Quota|Is gateway dropping|
|60%|15%|10%|15%|Yes|


## Your network components
In order to work with ATP, make sure to check that the following components are set up.

### Port mirroring
If you are using ATP Gateways, you have to set up port mirroring for the domain controllers that are monitored and set the ATP Gateway as the destination using the physical or virtual switches. Another option is to use network TAPs. ATP works if some but not all of your domain controllers are monitored, but detections are less effective.

While port mirroring mirrors all the domain controller network traffic to the ATP Gateway, only a small percentage of that traffic is then sent, compressed, to the ATP Center for analysis.

Your domain controllers and the ATP Gateways can be physical or virtual, see [Configure port mirroring](configure-port-mirroring.md) for more information.


### Events
To enhance ATP detection of Pass-the-Hash, Brute Force, Modification to sensitive groups and Honey Tokens, ATP needs the following Windows events: 4776, 4732, 4733, 4728, 4729, 4756, 4757. These can either be read automatically by the ATP Lightweight Gateway or in case the ATP Lightweight Gateway is not deployed, it can be forwarded to the ATP Gateway in one of two ways, by configuring the ATP Gateway to listen for SIEM events or by [Configuring Windows Event Forwarding](#configuring-windows-event-forwarding).

-   Configuring the ATP Gateway to listen for SIEM events <br>Configure your SIEM to forward specific Windows events to ATP. ATP supports a number of SIEM vendors. For more information, see [Configure event collection](configure-event-collection.md).

-   Configuring Windows Event Forwarding<br>Another way ATP can get your events is by configuring your domain controllers to forward Windows events 4776, 4732, 4733, 4728, 4729, 4756 and 4757 to your ATP Gateway. This is especially useful if you don't have a SIEM or if your SIEM is not currently supported by ATP. For more information about Windows Event Forwarding in ATP, see [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding). This only applies to physical ATP Gateways - not to the ATP Lightweight Gateway.

## Related Videos
- [Choosing the right ATP Gateway type](https://channel9.msdn.com/Shows/Microsoft-Security/ATP-Deployment-Choose-the-Right-Gateway-Type)


## See Also
- [ATP prerequisites](ata-prerequisites.md)
- [ATP sizing tool](http://aka.ms/atasizingtool)
- [ATP capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)

