---
# required metadata

title: ATA event ID reference | Microsoft Docs 
description: Provides a list of ATA events IDs and their descriptions. 
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 3/21/2018
ms.topic: conceptual
ms.prod: advanced-threat-analytics
ms.service:
ms.technology:
ms.assetid: 5d639e84-2e37-43a9-9667-49be6c4fa8b7

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: arzinger

ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Advanced Threat Analytics version 1.9*


# ATA event ID reference

The ATA Center event viewer logs events for ATA. This article provides a list of event IDs and provides a description of each.

The events can be found here:

![event ID location](./media/event-id-location.png)

## ATA Health events

1001 – ATA Center database data drive free space health alert 

1003 – ATA Center overloaded health alert 

1004 – Certificate expiry health alert 

1005 – Center database disconnected health alert 

1006 – ATA Gateway directory services client account password expiry health alert 

1007 – ATA Gateway domain synchronizer not assigned health alert 

1008 – ATA Gateway capture network adapter faulted health alert 

1009 – ATA Gateway capture network adapter missing health alert 

1010 – ATA Gateway directory services client connectivity health alert 

1011 – ATA Gateway disconnected health alert 

1012 – ATA Gateway overloaded event activities health alert 

1013 – ATA Gateway overloaded network activities health alert 

1014 – Center mail health alert 

1015 – Center Syslog health alert 

1016 – ATA Gateways outdated health alert 

1017 – Center not receiving traffic health alert 

1018 – ATA Gateway start-failure health alert 

1019 – ATA Gateway low memory health alert 

1020 – ATA Gateway RADIUS event listener health alert 

1021 – ATA Gateway Syslog event listener health alert 

1022 – ATA Center external IP address resolution failure health alert 
 
## ATA suspicious activity events

2001 – Abnormal behavior suspicious activity 

2002 – Abnormal protocol suspicious activity 

2003 – Account enumeration suspicious activity 

2004 – LDAP brute force suspicious activity 

2006 – Directory services replication suspicious activity 

2007 – DNS reconnaissance suspicious activity 

2008 – Encryption downgrade suspicious activity 

2012 – Enumerate sessions suspicious activity 

2013 – Forged PAC suspicious activity 

2014 – Honeytoken activity suspicious activity 

2016 – Massive object deletion suspicious activity 

2017 – Pass the hash suspicious activity 

2018 – Pass the ticket suspicious activity 

2019 – Remote execution suspicious activity 

2020 – Retrieve data protection backup key suspicious activity 

2021 – SAMR reconnaissance suspicious activity 

2022 – Golden ticket suspicious activity 

2023 – Brute force suspicious activity 

2024 - Abnormal sensitive group membership change suspicious activity  

## ATA auditing events

3001 – Change to ATA configuration 

3002 – ATA Gateway added

3003 – ATA Gateway deleted

3004 - ATA license activated

3005 – Log in to ATA console

3006 – Manual change to health activity status 

3007 – Manual change to suspicious activity status 


## See Also
- [ATA prerequisites](ata-prerequisites.md)
- [ATA capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
