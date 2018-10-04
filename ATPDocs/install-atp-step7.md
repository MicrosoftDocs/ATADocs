---
# required metadata

title: Azure Advanced Threat Protection configure detection exclusions and honeytoken accounts  | Microsoft Docs
description: Configuration of detection exclusions and honeytoken user accounts.
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 10/04/2018
ms.topic: conceptual
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 1ad5e923-9bbd-4f56-839a-b11a9f387d4b

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


<<<<<<< HEAD
# Configure detection exclusions and honeytoken accounts
=======

# Install Azure ATP - Step 7

> [!div class="step-by-step"]
> [« Step 6](install-atp-step6-vpn.md)
> [Step 8 »](install-atp-step8-samr.md)

## Step 7. Configure detection exclusions and honeytoken accounts
>>>>>>> 209d7e7162816a4c9e6e0ec0ff8d02f771e12d04

Azure ATP enables the exclusion of specific IP addresses or users from a number of detections. 

For example, a **DNS Reconnaissance exclusion** could be a security scanner that uses DNS as a scanning mechanism. The exclusion helps Azure ATP ignore such scanners.  

Azure ATP also enables the configuration of honeytoken accounts, which are used as traps for malicious actors - any authentication associated with these honeytoken accounts (normally dormant), triggers an alert.

To configure, follow these steps:

1.  From the Azure ATP portal, click on the settings icon and select **Configuration**.

    ![Azure ATP configuration settings](media/atp-config-menu.png)

2.  Under **Detection**, click **Entity tags**.

3. Under **Honeytoken accounts**, enter the Honeytoken account name and click the **+** sign. The Honeytoken accounts field is searchable and automatically displays entities in your network. Click **Save**.

   ![Honeytoken](media/honeytoken-sensitive.png)

4. Click **Exclusions**. Enter a user account or IP address to be excluded from the detection, for each type of threat. 
5. Click the *plus* sign. The **Add entity** (user or computer) field is searchable and will autofill with entities in your network. For more information, see [Excluding entities from detections](excluding-entities-from-detections.md) and the [suspicious activity guide](suspicious-activity-guide.md).

   ![Exclusions](media/exclusions.png)

6.  Click **Save**.


Congratulations, you have successfully deployed Azure Advanced Threat Protection!

Check the attack time line to view detected suspicious activities and search for users or computers and view their profiles.

Azure ATP scanning for suspicious activities starts immediately. Some detections, such as Abnormal Group Modifications, require a learning period and aren't available immediately after Azure ATP deployment.


<<<<<<< HEAD
=======

> [!div class="step-by-step"]
> [« Step 6](install-atp-step6-vpn.md)
> [Step 8 »](install-atp-step8-samr.md)

>>>>>>> 209d7e7162816a4c9e6e0ec0ff8d02f771e12d04
## See Also
- [Azure ATP sizing tool](http://aka.ms/aatpsizingtool)
- [Configure event collection](configure-event-collection.md)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Check out the zure ATP forum!](https://aka.ms/azureatpcommunity)
