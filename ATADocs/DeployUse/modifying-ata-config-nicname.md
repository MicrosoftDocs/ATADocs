---
# required metadata

title: Change ATA configuration - name of the capture network adapter | Microsoft Advanced Threat Analytics
description: Describes how to change the name of the network adapter that is configured as a Capture network adapter without ending ATA Gateway connectivity
keywords:
author: rkarlin
manager: stevenpo
ms.date: 04/28/2016
ms.topic: article
ms.prod: identity-ata
ms.service: advanced-threat-analytics
ms.technology: security
ms.assetid: 3225a81e-0395-43ca-9a48-0cbe7171e5de

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Change ATA configuration - name of the capture network adapter

>[!div class="step-by-step"]
[« Domain connectivity password](modifying-ata-config-dcpassword.md)

## Change the name of the ATA Gateway capture network adapter
If you change the name of the network adapter that is currently configured as a Capture network adapter, this will cause the ATA Gateway server not to start. In order to smoothly change the name without ending ATA Gateway connectivity, follow this process:

1.  In the ATA Gateway configuration page, unselect the network adapter  you want to rename, and select another network adapter as the capture network adapter in its place. This can be an interim network adapter or even the management network adapter. During this time, ATA will not capture the domain controller's port-mirrored traffic. Save the new configuration.

2.  On the ATA Gateway, rename the network adapter, by opening your Control Panel and selecting Network Connections.

3.  Then, go back into the ATA console's ATA Gateway configuration page. You may have to refresh the page, and then you should see the network adapter with the new name in the list. Unselect the adapter you selected in step 1, and select the newly named adapter. Finally, save the new configuration.

If you renamed your network adapter without following this process, your ATA Gateway won’t start and you will get this error on the ATA Gateway in Microsoft.Tri.Gateway-Errors.log log file. In the example below, **Capture** would be the original name of the network adapter you set:

`Error [NetworkListener] Microsoft.Tri.Infrastructure.ExtendedException: Unavailable network adapters [UnavailableCaptureNetworkAdapterNames=Capture]`

To correct this problem, rename the network adapter  back to the name it was originally called when you set up ATA, and then go through the process described above for changing the name.

>[!div class="step-by-step"]
[« Domain connectivity password](modifying-ata-config-dcpassword.md)


## See Also
- [Working with the ATA Console](../understand/working-with-ata-console.md)
- [Install ATA](install-ata.md)
- [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
