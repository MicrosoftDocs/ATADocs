---
# required metadata

title: Install Azure Threat Protection - Step 3 | Microsoft Docs
description: Step three of installing ATP helps you download the ATP Standalone Sensor setup package.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 95bb4ec1-841f-41b7-92fe-fbd144085724

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Threat Protection*



# Install ATP - Step 3

>[!div class="step-by-step"]
[« Step 2](install-ata-step2.md)
[Step 4 »](install-ata-step4.md)

## Step 3. Download the ATP Standalone Sensor setup package
After configuring the domain connectivity settings, you can download the ATP Standalone Sensor setup package. The ATP Standalone Sensor can be installed on a dedicated server or on a domain controller. If you install it on a domain controller, it is installed as an ATP Sensor. For more information on the ATP Sensor, see [ATP Architecture](ata-architecture.md). 

Click **Download** in the list of steps at the top of the page to go to the **Sensors** page.

![ATP Standalone Sensor configuration settings](media/atp-sensor-config.png)

> [!NOTE] 
> To reach the Sensor configuration screen later, click the **settings icon** (upper right corner) and select **Configuration**, then, under **System**, click **Standalone Sensors**.  

1.  Click **Sensors**.
2.  Save the package locally.
3.  Copy the package to the dedicated server or domain controller onto which you are installing the ATP Standalone Sensor. Alternatively, you can open the ATP Console from the dedicated server or domain controller and skip this step.

The zip file includes the following files:

-   ATP Standalone Sensor installer

-   Configuration setting file with the required information to connect to the Azure ATP cloud service


>[!div class="step-by-step"]
[« Step 2](install-ata-step2.md)
[Step 4 »](install-ata-step4.md)


## Related Videos
- [ATP Deployment Overview](https://channel9.msdn.com/Shows/Microsoft-Security/Overview-of-ATP-Deployment-in-10-Minutes)
- [Choosing the right ATP Standalone Sensor type](https://channel9.msdn.com/Shows/Microsoft-Security/ATP-Deployment-Choose-the-Right-Gateway-Type)

## See Also
- [ATP POC deployment guide](http://aka.ms/atapoc)
- [ATP sizing tool](http://aka.ms/atasizingtool)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATP prerequisites](ata-prerequisites.md)
