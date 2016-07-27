---
# required metadata

title: Install ATA - Step 3 | Microsoft ATA
description: Step three of installing ATA helps you download the ATA Gateway setup package.
keywords:
author: rkarlin
manager: stevenpo
ms.date: 04/28/2016
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology: security
ms.assetid: 7fb024e6-297a-4ad9-b962-481bb75a0ba3

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Install ATA - Step 3

>[!div class="step-by-step"]
[« Step 2](install-ata-step2.md)
[Step 4 »](install-ata-step4.md)

## Step 3. Download the ATA Gateway setup package
After configuring the domain connectivity settings you can download the ATA Gateway setup package. The ATA Gateway can be installed on a dedicated server or on a domain controller. If you install it on a domain controller, it will be installed as an ATA Lightweight Gateway. For more information on the ATA Lightweight Gateway, see [ATA Architecture](/advanced-threat-analytics/plan-design/ata-architecture). 

To download the ATA Gateway package:

1.  From the ATA Console, click on the settings icon and select **Configuration**.

    ![ATA gateway configuration settings](media/ATA-config-icon.JPG)

2.  In the **ATA Gateways** tab, click **Download ATA Gateway Setup**.

3.  Save the package locally.
4.  Copy the package to the dedicated server or domain controller onto which you are installing the ATA Gateway. Alternatively, you can open the ATA Console from the dedicated server or domain controller and skip this step.

The zip file includes the following:

-   ATA Gateway installer

-   Configuration setting file with the required information to connect to the ATA Center


>[!div class="step-by-step"]
[« Step 2](install-ata-step2.md)
[Step 4 »](install-ata-step4.md)

## See Also

- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATA prerequisites](/advanced-threat-analytics/plan-design/ata-prerequisites)
