---
# required metadata

title: Configure Windows Event collection Azure Advanced Threat Protection | Microsoft Docs
description: In this step of installing ATP, you configure Windows Event collection.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 02/19/2020
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 88692d1a-45a3-4d54-a549-4b5bba6c037b

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:
---

# Configure Windows Event collection

To enhance threat detection capabilities, Azure Advanced Threat Protection (Azure ATP) needs the following Windows Events: 4776, 4732, 4733, 4728, 4729, 4756, 4757, 7045 and 8004. These events can either be read automatically by the Azure ATP sensor or in case the Azure ATP sensor is not deployed, they can be forwarded to the Azure ATP standalone sensor in one of two ways, by [configuring the Azure ATP standalone sensor](configure-event-forwarding.md) to listen for SIEM events or by [Configuring Windows Event Forwarding](configure-event-forwarding.md).

> [!NOTE]
>
> - Azure ATP standalone sensors do not support all data source types, resulting in missed detections. For full coverage of your environment, we recommend deploying the Azure ATP sensor.
> - It is important to review and verify your [audit policies](atp-advanced-audit-policy.md) before enabling event collection to ensure that the domain controllers are properly configured to record the necessary events.

In addition to collecting and analyzing network traffic to and from the domain controllers, Azure ATP can use Windows events to further enhance detections. Azure ATP uses Windows event 4776 and 8004 for NTLM, which enhances various detections and events 4732, 4733, 4728, 4729, 4756, 4757 and 7045 and 8004 for enhancing detection of sensitive group modifications and service creation. These can be received from your SIEM or by setting Windows Event Forwarding from your domain controller. Events collected provide Azure ATP with additional information that is not available via the domain controller network traffic.

> [!NOTE]
> Domain group policies to collect Windows Event 8004 should **only** be applied to domain controllers.

## NTLM authentication using Windows Event 8004

To configure Windows Event 8004 collection:

1. Navigate to: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
2. Configure or create a **domain group policy** which is applied to the domain controllers in each domain as follows:
   - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = **Audit All**
   - Network security: Restrict NTLM: Audit NTLM authentication in this domain = **Enable all**
   - Network security: Restrict NTLM: Audit Incoming NTLM Traffic = **Enable auditing for all accounts**

When Windows Event 8004 is parsed by Azure ATP Sensor, Azure ATP NTLM authentications activities are enriched with the server accessed data.

## See Also

- [Azure ATP sizing tool](https://aka.ms/aatpsizingtool)
- [Azure ATP SIEM log reference](cef-format-sa.md)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
