---
# required metadata

title: Configure Azure ATP sensor settings quickstart | Microsoft Docs
description: Step five of installing Azure ATP helps you configure settings for your Azure ATP standalone sensor.
author: mlottner
ms.author: mlottner
ms.date: 02/06/2018
ms.topic: quickstart
ms.service: azure-advanced-threat-protection


# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Quickstart: Configure Azure ATP sensor settings

In this quickstart, you'll configure the Azure ATP sensor settings to start seeing data. You'll need to do additional configuration and integration to take advantage of Azure ATP's capabilities.  

## Prerequisites

- An [Azure ATP instance](install-atp-step1.md) that's [connected to Active Directory](install-atp-step2.md).
- A downloaded copy of your [ATP sensor setup package](install-atp-step3.md) and the access key.

## Configure sensor settings

After the Azure ATP sensor is installed, do the following steps to configure the Azure ATP sensor settings.

1.  In the Azure ATP portal, go to **Configuration** and, under the **System** section, select **Sensors**.
   
    ![Configure sensor settings image](media/atp-sensor-config.png)


2. Click on the sensor you want to configure and enter the following information:

   ![Configure sensor settings image](media/atp-sensor-config-2.png)

   - **Description**: Enter a description for the Azure ATP sensor (optional).
   - **Domain Controllers (FQDN)** (required for the Azure ATP standalone sensor, this can't be changed for the Azure ATP sensor): Enter the complete FQDN of your domain controller and click the plus sign to add it to the list. For example,  **dc01.contoso.com**

     The following information applies to the servers you enter in the **Domain Controllers** list:
     - All domain controllers whose traffic is being monitored via port mirroring by the Azure ATP standalone sensor must be listed in the **Domain Controllers** list. If a domain controller isn't listed in the **Domain Controllers** list, detection of suspicious activities might not function as expected.
     - At least one domain controller in the list should be a global catalog. This enables Azure ATP to resolve computer and user objects in other domains in the forest.

   - **Capture Network adapters** (required):
   
    - For Azure ATP sensors, all network adapters that are used for communication with other computers in your organization.
    - For Azure ATP standalone sensor on a dedicated server, select the network adapters that are configured as the destination mirror port. These network adapters receive the mirrored domain controller traffic.

  - **Domain synchronizer candidate**: 
    
    - The domain synchronizer is responsible for synchronization between Azure ATP and your Active Directory domain. Depending on the size of the domain, the initial synchronization may take time and is resource-intensive. Azure ATP recommends setting at least one domain controller as the domain synchronizer candidate per domain. Failure to select at least one domain controller as the domain synchronizer candidate means Azure ATP will only passively scan your network and may not be able to collect all Active Directory changes and entity details. At least one designated **domain synchronizer candidate** per domain ensures Azure ATP is actively scanning your network at all times and able to collect all Active Directory changes and entity values.
  
    - By default, Azure ATP sensors aren't domain synchronizer candidates, while Azure ATP standalone sensors are. To manually set an Azure ATP sensor as a domain synchronizer candidate, switch the **Domain synchronizer candidate** toggle option to **ON** in the configuration screen.
        
    - It's recommended that you disable any remote site Azure ATP sensor(s) from being domain synchronizer candidates.
   
    - Don't set read-only domain controllers as domain synchronizer candidates. For more information about Azure ATP domain synchronization, see [Azure ATP architecture](atp-architecture.md#azure-atp-sensor-features).
  
3. Click **Save**.


## Validate installations
To validate that the Azure ATP sensor has been successfully deployed, check the following steps:

1. Check that the service named **Azure Advanced Threat Protection sensor** is running. After you save the Azure ATP sensor settings, it might take a few seconds for the service to start.

2. If the service doesn't start, review the “Microsoft.Tri.sensor-Errors.log” file located in the following default folder, “%programfiles%\Azure Advanced Threat Protection sensor\Version X\Logs”.
 
   >[!NOTE]
   > The version of Azure ATP updates frequently, to check the latest version, in the Azure ATP portal, go to **Configuration** and then **About**. 

3. Go to your Azure ATP instance URL. In the Azure ATP portal, search for something in the search bar, such as a user or group on your domain.

## Next steps

- [Proxy configuration](configure-proxy.md)
- [Advanced Audit Policy](atp-advanced-audit-policy.md)
- [Configure Azure ATP to make remote calls to SAM](install-atp-step8-samr.md)


## Join the Community

Have more questions, or an interest in discussing Azure ATP and related security with others? Join the [Azure ATP Community](https://aka.ms/azureatpcommunity) today!
