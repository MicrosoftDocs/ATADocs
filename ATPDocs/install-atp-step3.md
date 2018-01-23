---
# required metadata

title: Install Azure Threat Protection - Step 3 | Microsoft Docs
description: Step three of installing ATP helps you download the ATP Gateway setup package.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
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

*Applies to: Azure Threat Protection *



# Install ATP - Step 3

>[!div class="step-by-step"]
[« Step 2](install-ata-step2.md)
[Step 4 »](install-ata-step4.md)

## Step 3. Download the ATP Gateway setup package
After configuring the domain connectivity settings, you can download the ATP Gateway setup package. The ATP Gateway can be installed on a dedicated server or on a domain controller. If you install it on a domain controller, it is installed as an ATP Lightweight Gateway. For more information on the ATP Lightweight Gateway, see [ATP Architecture](ata-architecture.md). 

Click **Download Gateway Setup** in the list of steps at the top of the page to go to the **Gateways** page.

![ATP gateway configuration settings](media/ATA_1.7-welcome-download-gateway.PNG)

> [!NOTE] 
> To reach the Gateway configuration screen later, click the **settings icon** (upper right corner) and select **Configuration**, then, under **System**, click **Gateways**.  

1.  Click **Gateway Setup**.
  ![Download ATP Gateway Setup](media/download-gateway-setup.png)
2.  Save the package locally.
3.  Copy the package to the dedicated server or domain controller onto which you are installing the ATP Gateway. Alternatively, you can open the ATP Console from the dedicated server or domain controller and skip this step.

The zip file includes the following files:

-   ATP Gateway installer

-   Configuration setting file with the required information to connect to the ATP Center


>[!div class="step-by-step"]
[« Step 2](install-ata-step2.md)
[Step 4 »](install-ata-step4.md)


## Related Videos
- [ATP Deployment Overview](https://channel9.msdn.com/Shows/Microsoft-Security/Overview-of-ATP-Deployment-in-10-Minutes)
- [Choosing the right ATP Gateway type](https://channel9.msdn.com/Shows/Microsoft-Security/ATP-Deployment-Choose-the-Right-Gateway-Type)

## See Also
- [ATP POC deployment guide](http://aka.ms/atapoc)
- [ATP sizing tool](http://aka.ms/atasizingtool)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATP prerequisites](ata-prerequisites.md)
