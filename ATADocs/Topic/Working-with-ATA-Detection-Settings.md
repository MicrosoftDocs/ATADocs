---
title: Working with ATA Detection Settings
ms.custom: 
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology: 
  - security
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: f4f2ae30-4849-4a4f-8f6d-bfe99a32c746
author: Rkarlin
---
# Working with ATA Detection Settings
The **Detection** configuration page lets you set a list of IP addresses and subnets that have unusual circumstances and should be handled slightly differently than other entities on your network.

## Setting up detection
On the **Detection** page you can define the following items:

-   **Short-term lease subnets** - If your organization has any subnets on which the IP addresses are very short-term, for example, VPN IP address subnets or Wi-Fi subnets, it is important to input these IP addresses and subnets into ATA so that ATA knows to store the association between a computer and an IP address from these ranges for a shorter period of time than it would for other IP addresses.

-   **Honeytoken account SIDs** – This is a user account that should have no network activities. This account will be configured as the ATA Honeytoken user. If someone attempts to use this user account ATA will create a suspicious activity and is an indication of malicious activity. To configure the Honeytoken user you will need the SID of the user account, not the user name.

You can exclude IP addresses from the following detections. If you enter an IP address in one of these lists, ATA will exclude that IP address from this specific type of detected activity.

-   DNS Reconnaissance IP address exclusions

-   Pass-the-Ticket IP address exclusions

## See Also
[Working with Suspicious Activities](../Topic/Working-with-Suspicious-Activities.md)
 [Modifying ATA Configuration](../Topic/Modifying-ATA-Configuration.md)
 [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)

