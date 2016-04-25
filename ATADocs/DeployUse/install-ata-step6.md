---
# required metadata

title: Install ATA | Microsoft Advanced Threat Analytics
description: In the final step of installing ATA, you configure the short-term lease subnets and the Honeytoken user.
keywords:
author: rkarlin
manager: stevenpo
ms.date: 04/28/2016
ms.topic: get-started-article
ms.prod: identity-ata
ms.service: advanced-threat-analytics
ms.technology: security
ms.assetid: 8980e724-06a6-40b0-8477-27d4cc29fd2b

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Install ATA - Step 6

>[!div class="step-by-step"]
[« Step 5](install-ata-step5.md)

## Step 6. Configure short-term lease subnets and Honeytoken user
Short-term lease subnets are subnets in which the IP address assignment changes very rapidly - within seconds or minutes. For example, IP addresses used for your VPNs and Wi-Fi IP addresses. To enter the list of short-term lease subnets used in your organization, follow these steps:

1.  From the ATA Console on the ATA Gateway machine, click on the settings icon and select **Configuration**.

    ![ATA configuration settings](media/ATA-config-icon.JPG)

2.  Under **Detection**, enter the following for short-term lease subnets. Enter the short-term lease subnets using slash notation format, for example:  `192.168.0.0/24` and click the plus sign.

3.  For the Honeytoken account SIDs, enter the SID for the user account that will have no network activity, and click the plus sign. For example: `S-1-5-21-72081277-1610778489-2625714895-10511`.

    > [!NOTE]
    > To find the SID for a user, run the following Windows PowerShell cmdlet `Get-ADUser UserName`.

4.  Configure exclusions: You can configure IP addresses to be excluded from specific suspicious activities. See [Working with ATA detection settings](working-with-detection-settings.md) for more information.

5.  Click **Save**.

![Save changes](media/ATA-VPN-Subnets.JPG)

Congratulations, you have successfully deployed Microsoft Advanced Threat Analytics!

Check the attack time line to view detected suspicious activities and search for users or computers and view their profiles.

Remember that it takes a minimum of three weeks for ATA to build behavioral profiles, so during the first three weeks you will not see any  suspicious behavior activities.


>[!div class="step-by-step"]
[« Step 5](install-ata-step5.md)


## See Also

- [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
- [Configure event collection](../plandesign/configure-event-collection.md)
- [ATA prerequisites](../plandesign/ata-prerequisites.md)
