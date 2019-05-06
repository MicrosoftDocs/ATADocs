---
# required metadata

title: Install Advanced Threat Analytics - Step 5 | Microsoft Docs
description: Step five of installing ATA helps you configure settings for your ATA Gateway.
keywords:
author: rkarlin
ms.author: rkarlin
manager: rkarlin
ms.date: 3/21/2018
ms.topic: conceptual
ms.prod: advanced-threat-analytics
ms.technology:
ms.assetid: 2a5b6652-2aef-464c-ac17-c7e5f12f920f

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Install ATA - Step 5

*Applies to: Advanced Threat Analytics version 1.9*

> [!div class="step-by-step"]
> [« Step 4](install-ata-step4.md)
> [Step 6 »](install-ata-step6.md)


## Step 5. Configure the ATA Gateway settings

After the ATA Gateway was installed, perform the following steps to configure the settings for the ATA Gateway.

1. In the ATA Console, go to **Configuration** and, under **System**, select **Gateways**.
   
    ![Configure gateway settings image](media/ata-gw-config-1.png)


2. Click on the Gateway you want to configure and enter the following information:

   ![Configure gateway settings image](media/ATA-Gateways-config-2.png)

   - **Description**: Enter a description for the ATA Gateway (optional).
   - **Port Mirrored Domain Controllers (FQDN)** (required for the ATA Gateway, this cannot be changed for the ATA Lightweight Gateway): Enter the complete FQDN of your domain controller and click the plus sign to add it to the list. For example,  **dc01.contoso.com**

   The following information applies to the servers you enter in the **Domain Controllers** list:  

   - All domain controllers whose traffic is being monitored via port mirroring by the ATA Gateway must be listed in the **Domain Controllers** list. If a domain controller is not listed in the **Domain Controllers** list, detection of suspicious activities might not function as expected.  
   - At least one domain controller in the list should be a global catalog. This enables ATA to resolve computer and user objects in other domains in the forest.

   - **Capture Network adapters** (required):
   - For an ATA Gateway on a dedicated server, select the network adapters that are configured as the destination mirror port. These receive the mirrored domain controller traffic.
   - For an ATA Lightweight Gateway, this should be all the network adapters that are used for communication with other computers in your organization.
  
   - **Domain synchronizer candidate**: Any ATA Gateway set to be a domain synchronizer candidate can be responsible for synchronization between ATA and your Active Directory domain. Depending on the size of the domain, the initial synchronization might take some time and is resource-intensive. By default, only ATA Gateways are set as Domain synchronizer candidates.
   It is recommended that you disable any remote site ATA Gateways from being Domain synchronizer candidates.
   If your domain controller is read-only, do not set it as a Domain synchronizer candidate. For more information, see [ATA architecture](ata-architecture.md#ata-lightweight-gateway-features).

   > [!NOTE] 
   > It will take a few minutes for the ATA Gateway service to start the first time after installation because it builds the cache of the network capture parsers.
   > The configuration changes are applied to the ATA Gateway on the next scheduled sync between the ATA Gateway and the ATA Center.

3. Optionally, you can set the [Syslog listener and Windows Event Forwarding Collection](configure-event-collection.md). 
4. Enable **Update ATA Gateway automatically** so that in upcoming version releases when you update the ATA Center, this ATA Gateway is automatically updated.

5. Click **Save**.


## Validate installations
To validate that the ATA Gateway has been successfully deployed, check the following steps:

1.  Check that the service named **Microsoft Advanced Threat Analytics Gateway** is running. After you save the ATA Gateway settings, it might take a few minutes for the service to start.

2.  If the service does not start, review the “Microsoft.Tri.Gateway-Errors.log” file located in the following default folder, “%programfiles%\Microsoft Advanced Threat Analytics\Gateway\Logs” and Check [ATA Troubleshooting](troubleshooting-ata-known-errors.md) for help.

3.  If this is the first ATA Gateway installed, after a few minutes, log into the ATA Console and open the notification pane by swiping the right side of the screen open. You should see a list of **Entities Recently Learned** in the notification bar on the right side of the console.

4.  On the desktop, click the **Microsoft Advanced Threat Analytics** shortcut to connect to the ATA Console. Log in with the same user credentials that you used to install the ATA Center.
5.  In the console, search for something in the search bar, such as a user or a group on your domain.
6.  Open Performance Monitor. In the Performance tree, click on **Performance Monitor** and then click the plus icon to **Add a Counter**. Expand **Microsoft ATA Gateway** and scroll down to **Network Listener PEF Captured Messages/Sec** and add it. Then, make sure you see activity on the graph.

    ![Add performance counters image](media/ATA-performance-monitoring-add-counters.png)


> [!div class="step-by-step"]
> [« Step 4](install-ata-step4.md)
> [Step 6 »](install-ata-step6.md)



## Related Videos
- [ATA Deployment Overview](https://channel9.msdn.com/Shows/Microsoft-Security/Overview-of-ATA-Deployment-in-10-Minutes)
- [Choosing the right ATA Gateway type](https://channel9.msdn.com/Shows/Microsoft-Security/ATA-Deployment-Choose-the-Right-Gateway-Type)


## See Also
- [ATA POC deployment guide](http://aka.ms/atapoc)
- [ATA sizing tool](http://aka.ms/atasizingtool)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATA prerequisites](ata-prerequisites.md)

