---
# required metadata

title: Install Azure Threat Protection - Step 5 | Microsoft Docs
description: Step five of installing ATP helps you configure settings for your ATP Gateway.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
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

*Applies to: Azure Threat Protection *



# Install ATP - Step 5

>[!div class="step-by-step"]
[« Step 4](install-ata-step4.md)
[Step 6 »](install-ata-step6.md)


## Step 5. Configure the ATP Gateway settings
After the ATP Gateway was installed, perform the following steps to configure the settings for the ATP Gateway.

1.  In the ATP Console, go to **Configuration** and, under **System**, select **Gateways**.
   
     ![Configure gateway settings image](media/ata-gw-config-1.png)


2.  Click on the Gateway you want to configure and enter the following information:

    ![Configure gateway settings image](media/ATP-Gateways-config-2.png)

  - **Description**: Enter a description for the ATP Gateway (optional).
  - **Port Mirrored Domain Controllers (FQDN)** (required for the ATP Gateway, this cannot be changed for the ATP Lightweight Gateway): Enter the complete FQDN of your domain controller and click the plus sign to add it to the list. For example,  **dc01.contoso.com**

      The following information applies to the servers you enter in the **Domain Controllers** list:
      - All domain controllers whose traffic is being monitored via port mirroring by the ATP Gateway must be listed in the **Domain Controllers** list. If a domain controller is not listed in the **Domain Controllers** list, detection of suspicious activities might not function as expected.
      - At least one domain controller in the list should be a global catalog. This enables ATP to resolve computer and user objects in other domains in the forest.

  - **Capture Network adapters** (required):
  - For an ATP Gateway on a dedicated server, select the network adapters that are configured as the destination mirror port. These receive the mirrored domain controller traffic.
  - For an ATP Lightweight Gateway, this should be all the network adapters that are used for communication with other computers in your organization.


  - **Domain synchronizer candidate**: Any ATP Gateway set to be a domain synchronizer candidate can be responsible for synchronization between ATP and your Active Directory domain. Depending on the size of the domain, the initial synchronization might take some time and is resource-intensive. By default, only ATP Gateways are set as Domain synchronizer candidates.
   It is recommended that you disable any remote site ATP Gateways from being Domain synchronizer candidates.
   If your domain controller is read-only, do not set it as a Domain synchronizer candidate. For more information, see [ATP architecture](ata-architecture.md#ata-lightweight-gateway-features).

  > [!NOTE] 
  > It will take a few minutes for the ATP Gateway service to start the first time after installation because it builds the cache of the network capture parsers.
  > The configuration changes are applied to the ATP Gateway on the next scheduled sync between the ATP Gateway and the ATP Center.

3. Optionally, you can set the [Syslog listener and Windows Event Forwarding Collection](configure-event-collection.md). 
4. Enable **Update ATP Gateway automatically** so that in upcoming version releases when you update the ATP Center, this ATP Gateway is automatically updated.

5. Click **Save**.


## Validate installations
To validate that the ATP Gateway has been successfully deployed, check the following steps:

1.  Check that the service named **Microsoft Azure Threat Protection Gateway** is running. After you save the ATP Gateway settings, it might take a few minutes for the service to start.

2.  If the service does not start, review the “Microsoft.Tri.Gateway-Errors.log” file located in the following default folder, “%programfiles%\Microsoft Azure Threat Protection\Gateway\Logs” and Check [ATP Troubleshooting](troubleshooting-ata-known-errors.md) for help.

3.  If this is the first ATP Gateway installed, after a few minutes, log into the ATP Console and open the notification pane by swiping the right side of the screen open. You should see a list of **Entities Recently Learned** in the notification bar on the right side of the console.

4.  On the desktop, click the **Microsoft Azure Threat Protection** shortcut to connect to the ATP Console. Log in with the same user credentials that you used to install the ATP Center.
5.  In the console, search for something in the search bar, such as a user or a group on your domain.
6.  Open Performance Monitor. In the Performance tree, click on **Performance Monitor** and then click the plus icon to **Add a Counter**. Expand **Microsoft ATP Gateway** and scroll down to **Network Listener PEF Captured Messages/Sec** and add it. Then, make sure you see activity on the graph.

    ![Add performance counters image](media/ATP-performance-monitoring-add-counters.png)


>[!div class="step-by-step"]
[« Step 4](install-ata-step4.md)
[Step 6 »](install-ata-step6.md)



## Related Videos
- [ATP Deployment Overview](https://channel9.msdn.com/Shows/Microsoft-Security/Overview-of-ATP-Deployment-in-10-Minutes)
- [Choosing the right ATP Gateway type](https://channel9.msdn.com/Shows/Microsoft-Security/ATP-Deployment-Choose-the-Right-Gateway-Type)


## See Also
- [ATP POC deployment guide](http://aka.ms/atapoc)
- [ATP sizing tool](http://aka.ms/atasizingtool)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATP prerequisites](ata-prerequisites.md)

