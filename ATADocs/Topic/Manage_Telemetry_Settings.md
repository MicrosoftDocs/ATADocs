---
title: Manage Telemetry Settings
ms.custom: na
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: 8c1c7a1b-a3de-4105-9fd0-08a061952172
author: Rkarlin
---
# Manage Telemetry Settings
Advanced Threat Analytics (ATA) collects anonymous telemetry data about ATA and transmits the data over an HTTPS connection to Microsoft servers.  This data is used by Microsoft to help improve future versions of ATA.

## Data collected
Collected data includes the following:

-   Performance counters from both the ATA Center    and the ATA Gateway

-   Product ID after ATA has been licensed

-   Deployment date of the ATA Center

-   Number of deployed ATA Gateways

-   The following Active Directory information:

    -   Domain ID for the domain whose name would be the first domain when sorted alphabetically

    -   Number of domain controllers

    -   Number of domain controllers monitored by ATA via port mirroring

    -   Number of Sites

    -   Number of Computers

    -   Number of Groups

    -   Number of Users

-   Suspicious Activities  – The following data is collected for each suspicious activity:

    (Computer names, user names, and IP addresses are **not** collected)

    -   Suspicious activity type

    -   Suspicious activity ID

    -   Status

    -   Start and End Time

    -   Input provided

### Disable data collection
To stop collecting and sending telemetry data to Microsoft follow the following steps.

1.  Log in to the ATA Console    click the three dots in the toolbar and select **About**.

2.  Uncheck the box for **Send us usage information to help improve your customer experience in the future**.

## See Also
[ATA Release Notes](../Topic/ATA_Release_Notes.md)
 [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)

