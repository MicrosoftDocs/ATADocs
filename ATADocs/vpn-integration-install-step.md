---
# required metadata

title: Install Advanced Threat Analytics - Step 7 | Microsoft Docs
description: In this step of installing ATA, you integrate your VPN.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 10/9/2017
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: e0aed853-ba52-46e1-9c55-b336271a68e7

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Advanced Threat Analytics version 1.8*



# Install ATA - Step 7

>[!div class="step-by-step"]
[« Step 5](install-ata-step5.md)
[Step 8 »](install-ata-step7.md)

## Step 7. Integrate VPN

### Configuring VPN

ATA collects VPN data that helps profile the locations from which computers connect to the network and to be able to detect abnormal VPN connections.

To configure VPN data in ATA:

1. Go to **Configuration** and then click the  **VPN** tab.

2. Enter the **Account shared secret** of your RADIUS server. To get the shared secret, refer to your VPN documentation.

 ![Configure ATA VPN](media/vpn.png)

3.	Once this is enabled, all ATA Gateways and Lightweight Gateways listen on port 1813 for RADIUS accounting events. 

4.	The VPN's RADIUS accounting events should be forwarded to any ATA Gateway or ATA Lightweight Gateway after this is configured.

5.	After the ATA Gateway receives the VPN events and sends them to the ATA Center for processing, the ATA Center needs Internet connectivity for HTTPS port 443 to be able to resolve the external IP addresses in the VPN events to their geolocation.

The call to resolve an external IP address to a location is anonymous. No personal identifier is sent in this call.

The supported VPN vendors are:
- Microsoft
- F5
- Check Point
- Cisco ASA




>[!div class="step-by-step"]
[« Step 6](install-ata-step5.md)
[Step 8 »](install-ata-step7.md)



## Related Videos
- [ATA Deployment Overview](https://channel9.msdn.com/Shows/Microsoft-Security/Overview-of-ATA-Deployment-in-10-Minutes)
- [Choosing the right ATA Gateway type](https://channel9.msdn.com/Shows/Microsoft-Security/ATA-Deployment-Choose-the-Right-Gateway-Type)


## See Also
- [ATA POC deployment guide](http://aka.ms/atapoc)
- [ATA sizing tool](http://aka.ms/atasizingtool)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATA prerequisites](ata-prerequisites.md)

