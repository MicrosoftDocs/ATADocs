---
# required metadata

title: Azure Advanced Threat Protection Network Name Resolution port policy check | Microsoft Docs
description: This article provides an overview of Azure ATP's Advanced Network Name Resolution port policy check.
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 03/24/2019
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 05a8e961-fb9f-49d0-9778-6f26664c2c08

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


# Azure ATP Network Name Resolution port policy check

Azure ATP detection capabilities rely on active Network Name Resolution (NNR) for visibility in certain scenarios, such as NetBios,RPC over NTLM, reverse and forward DNS. NNR enables Azure ATP to translate IP addresses used for communication with your domain, into a device name. To achieve a high rate of success with active NNR, the correct ports have to be accessible and open to Azure ATP sensors. Incorrect port settings leave critical event profiling and detections unavailable, resulting in unnecessary false positives, and incomplete Azure ATP coverage for your organization.

Methods and relevant ports:
 - NetBIOS – UDP port 137
 - NTLM over RPC - TCP port 135
 - TLS – TCP port 3389 

Use the following logic flow to understand how Azure ATP performs NNR. 
![Network Name Resolution (NNR) logic flow](media/atp-nnr-flow diagram.png)

To make it easier to verify the current status of each of your sensor's ports, Azure ATP checks the status of each port per sensor and issues sensor alerts for port settings that require modification. Each alert provides specific details of the sensor, the problematic policy as well as remediation suggestions.

![Low success rate Network Name Resolution (NNR) alert](media/atp-health-alert-audit-policy.png)

## Port recommendations 
- NetBIOS/ RPC over NTLM:
  - Check that the port is open for inbound communication from Azure ATP sensors, on all machines in the environment. 
  - Check all network configurations (such as firewalls), that could prevent communication to the relevant ports. 

 - Forward DNS:
    - Check that the sensor can reach the DNS server.  

 - Reverse DNS:
    - Check that the sensor can reach the DNS server and that reverse lookup is enabled. 


## See Also
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)
