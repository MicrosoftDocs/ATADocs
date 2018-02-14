---
# required metadata

title: Azure ATP event ID reference | Microsoft Docs 
description: Provides a list of Azure ATP events IDs and their descriptions. 
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/14/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: e06040b3-00be-49e8-8658-9d49dbada124

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: arzinger

ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*


# Azure ATP event ID reference

The Azure ATP cloud service event viewer logs events for ATP. This article provides a list of event IDs and provides a description of each.

The events can be found here:

![event ID location](./media/event-id-location.png)

## Azure ATP Health events

1001 – Azure ATP cloud service database data drive free space health alert 

1003 – Azure ATP cloud service overloaded health alert 

1004 – Certificate expiry health alert 

1005 – Center database disconnected health alert 

1006 – Azure ATP Standalone Sensor directory services client account password expiry health alert 

1007 – Azure ATP Standalone Sensor domain synchronizer not assigned health alert 

1008 – Azure ATP Standalone Sensor capture network adapter faulted health alert 

1009 – Azure ATP Standalone Sensor capture network adapter missing health alert 

1010 – Azure ATP Standalone Sensor directory services client connectivity health alert 

1011 – Azure ATP Standalone Sensor disconnected health alert 

1012 – Azure ATP Standalone Sensor overloaded event activities health alert 

1013 – Azure ATP Standalone Sensor overloaded network activities health alert 

1014 – Center mail health alert 

1015 – Center Syslog health alert 

1016 – Azure ATP Standalone Sensors outdated health alert 

1017 – Center not receiving traffic health alert 

1018 – Azure ATP Standalone Sensor start-failure health alert 

1019 – Azure ATP Standalone Sensor low memory health alert 

1020 – Azure ATP Standalone Sensor RADIUS event listener health alert 

1021 – Azure ATP Standalone Sensor Syslog event listener health alert 

1022 – Azure ATP cloud service external IP address resolution failure health alert 
 
## Azure ATP suspicious activity events

2001 – Abnormal behavior suspicious activity 

2002 – Abnormal protocol suspicious activity 

2003 – Account enumeration suspicious activity 

2004 – LDAP brute force suspicious activity 

2005 – Computer pre-authentication failed suspicious activity 

2006 – Directory services replication suspicious activity 

2007 – DNS reconnaissance suspicious activity 

2008 – Encryption downgrade suspicious activity 

2012 – Enumerate sessions suspicious activity 

2013 – Forged PAC suspicious activity 

2014 – Honeytoken activity suspicious activity 

2015 – LDAP clear text password suspicious activity 

2016 – Massive object deletion suspicious activity 

2017 – Pass the hash suspicious activity 

2018 – Pass the ticket suspicious activity 

2019 – Remote execution suspicious activity 

2020 – Retrieve data protection backup key suspicious activity 

2021 – SAMR reconnaissance suspicious activity 

2022 – Golden ticket suspicious activity 

2023 – Brute force suspicious activity 

2024 - Abnormal sensitive group membership change suspicious activity  

## Azure ATP auditing events

3001 – Change to Azure ATP configuration 

3002 – Azure ATP Standalone Sensor added

3003 – Azure ATP Standalone Sensor deleted

3004 - Azure ATP license activated

3005 – Log in to Azure ATP workspace portal

3006 – Manual change to health activity status 

3007 – Manual change to suspicious activity status 


## See Also

- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
