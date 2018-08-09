---
# required metadata

title: Azure Advanced Threat Protection mutli-forest support | Microsoft Docs
description: How to set up support for multiple Active Directory forests in Azure ATP.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 7/20/2018
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

# Install Azure ATP - Step 9

>[!div class="step-by-step"]
[« Step 8](install-atp-step8-samr.md)

## Step 9.  Set up Azure Advanced Threat Protection multi-forest support

Azure ATP can support organizations with multiple forests which gives you the ability monitor activity and profile users across forests. 

An enterprise organization may have several Active Directory forests - often used for different purposes, including legacy infrastructure from corporate mergers and acquisitions, geographical distribution, and security boundaries (red-forests). You can protect multiple forests using Azure ATP, reporting all the data to a single, primary workspace, providing you with the ability to monitor and investigate through a single pane of glass.

The ability to support multiple Active Directory forests enables the following:
-	You can view and investigate activities performed by users across multiple forests from a single pane of glass. 
-	Multi-forest support improves detection and reduces false positives by providing advanced Active Directory integration and account resolution. 
-	Because multi-foresst support removes the need for multiple workspaces, you have greater control and easier deployment, while your domain controllers are all monitored centrally from a single Azure ATP console which provides better monitoring alerts and reporting for cross-org coverage.


## How Azure ATP detects activities across multiple forests 

To detect cross-forest activities, Azure ATP sensors query domain controllers in remote forests to create profiles for all entities involved, including users and computers from remote forests. 

> [!NOTE]
> - Azure ATP sensors can be installed on all forests (if a minimum one-way trust exists).
> - The user you configure in the Azure ATP console under **Directory services** must be trusted in all the other forests.


If you have forests on which no Azure ATP sensors are installed, Azure ATP can still view and monitor activities originating from those forests. The ATP sensors installed can query all connected remote forest domain controllers to resolve users and machines and create profiles for each of them. 

## Installation requirements 

-	If Azure ATP standalone sensors are installed on standalone machines, rather than directly on the domain controllers, make sure the machines are allowed to communicate with all of remote forest domain controllers using LDAP. 
- The user you configure in the Azure ATP console under **Directory services** must be trusted in all the other forests and must have at least read only permission to perform LDAP queries of the domain controllers.

- In order for Azure ATP to communicated with the ATP sensors and ATP standalone sensors, open the following ports on each maching on which the ATP sensor is installed:

 
  |Protocol|Transport|Port|To/From|Direction|
  |----|----|----|----|----|
  |**Internet ports**||||
  |SSL (*.atp.azure.com)|TCP|443|Azure ATP cloud service|Outbound|
  |**Internal ports**||||			
  |LDAP|TCP and UDP|389|Domain controllers|Outbound|
  |Secure LDAP (LDAPS)|TCP|636|Domain controllers|Outbound|
  |LDAP to Global Catalog|TCP|3268|Domain controllers|Outbound|
  |LDAPS to Global Catalog|TCP|3269|Domain controllers|Outbound|


## Multi forest support network traffic impact 

When Azure ATP maps your forests, it uses a process that impacts the following:

-	After the Azure ATP sensor is running, it queries the remote Active Directory forests and retrieves a list of users and machine data for profile creation.
-	Every 5 minutes, each Azure ATP sensor queries one domain controller from each domain, from each forest, to map all the forests in the network.
-	Each Azure ATP sensor maps the forests using the “trustedDomain” object in Active Directory, by logging in and checking the trust type.
-	You may also see ad-hoc traffic when the ATP sensor detects cross forest activity. When this occurs, the ATP sensors will send an LDAP query to the relevant domain controllers in order retrieve entity information. 

## Known limitations
-	Interactive logons performed by users in one forest to access resources in another forest are not displayed in the Azure ATP dashboard.


>[!div class="step-by-step"]
[« Step 8](install-atp-step8-samr.md)


## See Also
- [ATA sizing tool](http://aka.ms/aatpsizingtool)
- [ATA architecture](atp-architecture.md)
- [Install ATA](install-atp-step1.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)

