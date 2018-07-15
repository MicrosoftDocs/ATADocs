---
# required metadata

title: Azure Advanced Threat Protection mutli-forest support | Microsoft Docs
description: How to set up support for multiple Active Directory forests in Azure ATP.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 7/15/2018
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: effca0f2-fcae-4fca-92c1-c37306decf84

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




# Azure Advanced Threat Protection multi-forest support

An enterprise organization may have several Active Directory forests - often used for different purposes, including legacy infrastructure from corporate mergers and acquisitions, geographical distribution, and security boundaries (red-forests). You can protect multiple forests using Azure ATP, reporting all the data to a single, primary workspace, providing you with the ability to monitor and investigate through a single pane of glass.

The ability to support multiple Active Directory forests enables the following:
-	You can view activities performed by users from multiple forests, accessing resources connected to Azure ATP sensors within each protected forest.
-	Multi-forest support provides a single pane of glass for investigation of entities across multiple forests. 
-	Improved detection and reduced false positives with improved AD account resolution. This reduces blind spots and enables more security alerts to be surfaced, while at the same time reducing false positives. 
-	Easier deployment control enabling you to monitor all domain controllers from a single place, providing better monitoring alerts and reporting for cross-org coverage.


## Detecting cross-forests activities 

To detect cross-forest activities, Azure ATP sensors query domain controllers in remote forests to create a profile of all entities involved, including users and computers from different forests. 

> [!NOTE]
> In order for this to work correctly, there must be a minimum of one-way trust between the forests, and the forest where Azure ATP sensors are installed on the trusted side.

In the following diagram, only forest A is protected by Azure ATP. Users from forest B have access to resources in forest A. Azure ATP is installed on forest A. It queries Active Directory in forest B, retrieves the full user profile and creates the relevant activities (interactive logon/resource access) in the user and computer profiles in Azure ATP.

In the following diagram, only forest A is protected by Azure ATP. Users from forest A have access to resources in forest B. Azure ATP is installed on forest A. It queries Active Directory in forest B, retrieves the full user profile and creates the relevant activities (interactive logon/resource access) in the user and computer profiles in Azure ATP.

> [!NOTE]
> The Azure ATP directory service user must be in a forest that is trusted by the other forests.


## Installation requirements 

-	If the Azure ATP standalone sensors are installed on standalone machines, rather than directly on the domain controllers, make sure the machines are allowed to communicate with all of remote forest domain controllers using LDAP. 
- Make sure the service account used for Azure ATP directory services has read only permission to perform LDAP queries of the domain controllers.

- Open the following ports on XXX to support multi-forest:

 
|Protocol|Transport|Port|To/From|Direction|
|----|----|----|----|----|
|**Internet ports**||||
|SSL (*.atp.azure.com)|TCP|443|Azure ATP cloud service|Outbound|
|**Internal ports**||||			
|LDAP|TCP and UDP|389|Domain controllers|Outbound|
|Secure LDAP (LDAPS)|TCP|636|Domain controllers|Outbound|
|LDAP to Global Catalog|TCP|3268|Domain controllers|Outbound|
|LDAPS to Global Catalog|TCP|3269|Domain controllers|Outbound|

- LDAP communication occurs over port TCP 389, or over SSL TCP 636. 
-	Querying the Global Catalog occurs over LDAP TCP 3268, or over SSL using TCP 3269.

## Multi forest support network traffic impact 

-	After the Azure ATP sensor is running, it will query the remote Active Directory forests to retrieve a list of users and machine data so that profiles can be created.
-	Every 5 minutes, each Azure ATP sensor queries one domain controller from each domain, from each forest, to map all the forests in the network.
-	Each Azure ATP sensor maps the forests using the “trustedDomain” object in Active Directory, by logging in and checking the trust type.
-	XXXX Ad-hoc cross forest traffic will occur when the sensor will see a network activity contains entities from multiple forest. The sensors will LDAP query the relevant domain controllers in order to get information on the entities. 

## Known limitations
-	Interactive logons performed by users from forest A who access resources in forest B are not displayed in the Azure ATP dashboard.



## See Also
- [ATA sizing tool](http://aka.ms/aatpsizingtool)
- [ATA architecture](atp-architecture.md)
- [Install ATA](install-atp-step1.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)

