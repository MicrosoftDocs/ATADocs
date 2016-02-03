---
title: ATA technical FAQ
ms.custom: na
ms.reviewer: na
ms.suite: na
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: a7d378ec-68ed-4a7b-a0db-f5e439c3e852
author: Rkarlin
---
# ATA technical FAQ
This article provides a list of frequently asked questions about ATA and provides insight and answers.

## ATA Frequently Asked Questions

|Question|What you should do to fix it...|
|------------|-----------------------------------|
|The ATA Gateway won't start, what should I do?|Look at the most recent error in the current error log (Where ATA is installed under the "Logs" folder).|
|How can I test ATA?|You can simulate suspicious activities which is an end to end test by doing one of the following:<br /><br />1.  DNS reconnaissance by using Nslookup.exe<br />2.  Remote execution by using psexec.exe<br /><br />This needs to run against the domain controller being monitored and not from the ATA Gateway.|
|How do I verify Windows Event Forwarding?|You can run the following from a command prompt in the directory:  **\Program Files\Microsoft Advanced Threat Analytics\Center\MongoDB\bin**:<br /><br />mongo ATA --eval "printjson(db.getCollectionNames())" &#124; find /C "NtlmEvents"`|
|Does ATA work with encrypted traffic?|Encrypted traffic will not be analyzed (for example: LDAPS, IPSEC ESP).|
|How many ATA Gateways do I need?|There are two things to consider when figuring out how many gateways you would need:<br /><br />-   The total amount of traffic your domain controllers produce determines the minimum number of ATA Gateways you need in order to handle your Active Directory environment, from a performance perspective.<br />    To read more on how to determine how much traffic your domain controllers produce, see [ATA Capacity Planning](../Topic/ATA_Capacity_Planning.md).<br />-   The operational limitations of port mirroring also determine how many ATA Gateways you need to support all your domain controllers, for example: per switch, per datacenter, per region – each environment has its own considerations.|
|How much storage do I need for ATA?|For every one full day with an average of 1000 packets/sec you need 1.5 GB of storage.<br /><br />For more information see, [ATA Capacity Planning](../Topic/ATA_Capacity_Planning.md).|
|Why are certain accounts sensitive?|This happens when an account is a member of certain groups which we designate as sensitive (for example: "Domain Admins").<br />To understand why an account is sensitive you can review its group membership to understand which sensitive groups it belongs to (the group that it belongs to can also be sensitive due to another group, so the same process should be performed until you locate the highest level sensitive group).|
|How do I monitor a virtual domain controller?|You can have either a virtual or physical ATA Gateways as described in [Configure Port Mirroring](../Topic/Configure_Port_Mirroring.md).  <br />The easiest way is to have a virtual ATA Gateway on every host where a virtual domain controller exists.<br />If your virtual domain controllers move between hosts, you need to perform one of the following:<br /><br />-   When the virtual domain controller moves to another host, preconfigure the ATA Gateway in that host to receive the traffic from the recently moved virtual domain controller.<br />-   Make sure that you affiliate the virtual ATA Gateway with the virtual domain controller so that if it is moved, the ATA Gateway moves with it.<br />-   There are some virtual switches that can send traffic between hosts.|
|How do I back up ATA?|There are 2 things to back up:<br /><br />-   The configuration of ATA, which is stored in the database and is automatically backed up every hour. <br />-   The traffic and events stored by ATA, which can be backed using any supported database backup procedure, for more information see [ATA Database Management](../Topic/ATA_Database_Management.md)|
|What can ATA detect?|For the full list of ATA detections, see [Microsoft Advanced Threat Analytics](../Topic/Microsoft_Advanced_Threat_Analytics.md).|
