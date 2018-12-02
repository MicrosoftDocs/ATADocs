---
# required metadata

title: Install Azure Advanced Threat Protection | Microsoft Docs
description: Step five of installing Azure ATP helps you configure settings for your Azure ATP standalone sensor.
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 10/04/2018
ms.topic: conceptual
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: d7c95f8c-04f8-4946-9bae-c27ed362fcb0

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



# Install Azure ATP - Step 5

> [!div class="step-by-step"]
> [« Step 4](install-atp-step4.md)
> [Step 6 »](install-atp-step6-vpn.md)



## Step 5. Configure the Azure ATP sensor settings
After the Azure ATP sensor is installed, perform the following steps to configure the Azure ATP sensor settings.

1.  In the Azure ATP portal, go to **Configuration** and, under **System**, select **sensor**.
   
     ![Configure sensor settings image](media/atp-sensor-config.png)


2.  Click on the sensor you want to configure and enter the following information:

    ![Configure sensor settings image](media/atp-sensor-config-2.png)

  - **Description**: Enter a description for the Azure ATP sensor (optional).
  - **Domain Controllers (FQDN)** (required for the Azure ATP standalone sensor, this cannot be changed for the Azure ATP sensor): Enter the complete FQDN of your domain controller and click the plus sign to add it to the list. For example,  **dc01.contoso.com**

      The following information applies to the servers you enter in the **Domain Controllers** list:
      - All domain controllers whose traffic is being monitored via port mirroring by the Azure ATP standalone sensor must be listed in the **Domain Controllers** list. If a domain controller is not listed in the **Domain Controllers** list, detection of suspicious activities might not function as expected.
      - At least one domain controller in the list should be a global catalog. This enables Azure ATP to resolve computer and user objects in other domains in the forest.

  - **Capture Network adapters** (required):
   
     - For an Azure ATP sensor, this should be all the network adapters that are used for communication with other computers in your organization.
    - For an Azure ATP standalone sensor on a dedicated server, select the network adapters that are configured as the destination mirror port. These receive the mirrored domain controller traffic.

    - **Domain synchronizer candidate**: By default, Azure ATP sensors are not domain synchronizer candidates, while Azure ATP standalone sensors are. To manually select an Azure ATP sensor as a domain syncronizer candidate, switch the **Domain synchronizer candidate** toggle option to **ON** in the configuration screen. 
    
        The domain synchronizer is responsible for synchronization between Azure ATP and your Active Directory domain. Depending on the size of the domain, the initial synchronization might take some time and is resource-intensive. 
   It is recommended that you disable any remote site Azure ATP sensor(s) from being domain synchronizer candidates.
   If your domain controller is read-only, do not set it as a domain synchronizer candidate. For more information about Azure ATP domain synchronization, see [Azure ATP architecture](atp-architecture.md#azure-atp-sensor-features)
  
3. Click **Save**.


## Validate installations
To validate that the Azure ATP sensor has been successfully deployed, check the following steps:

1.  Check that the service named **Azure Advanced Threat Protection sensor** is running. After you save the Azure ATP sensor settings, it might take a few seconds for the service to start.

2.  If the service does not start, review the “Microsoft.Tri.sensor-Errors.log” file located in the following default folder, “%programfiles%\Azure Advanced Threat Protection sensor\Version X\Logs”.
 
 >[!NOTE]
 > The version of Azure ATP updates frequently, to check the latest version, in the Azure ATP portal, go to **Configuration** and then **About**. 

3.  Go to your Azure ATP instance URL. In the Azure ATP portal, search for something in the search bar, such as a user or a group on your domain.



> [!div class="step-by-step"]
> [« Step 4](install-atp-step4.md)
> [Step 6 »](install-atp-step6-vpn.md)



## See Also

- [Azure ATP sizing tool](http://aka.ms/aatpsizingtool)
- [Configure event collection](configure-event-collection.md)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
