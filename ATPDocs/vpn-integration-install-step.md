---
# required metadata

title: Install Azure Advanced Threat Protection - Step 6 | Microsoft Docs
description: In this step of installing ATP, you integrate your VPN.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/14/2018
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 0d9d2a1d-6c76-4909-b6f9-58523df16d4f

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*



# Install Azure ATP - Step 6

>[!div class="step-by-step"]
[« Step 5](install-atp-step5.md)
[Step 7 »](install-atp-step7.md)

## Step 6. Integrate VPN

Azure Advanced Threat Protection (ATP)  can collect accounting information from VPN solutions. When configured, the user's profile page includes information from the VPN connections, such as the IP addresses and locations where connections originated. This complements the investigation process by providing additional information on user activity as well as a new detection for abnormal VPN connections. The call to resolve an external IP address to a location is anonymous. No personal identifier is sent in this call.

Azure ATP integrates with your VPN solution by listening to RADIUS accounting events forwarded to the Azure ATP sensors. This mechanism is based on standard RADIUS Accounting ([RFC 2866](https://tools.ietf.org/html/rfc2866)), and the following VPN vendors are supported:

-	Microsoft
-	F5
-	Check Point
-	Cisco ASA

## Prerequisites

To enable VPN integration, make sure you set the following parameters:

-	Open port UDP 1813 on your Azure ATP standalone sensors and Azure ATP Sensors.

-	Connect the Azure ATP cloud service to the Internet so that it can query the location of incoming IP addresses.

The example below uses Microsoft Routing and Remote Access Server (RRAS) to describe the VPN configuration process.

If you’re using a third party VPN solution, consult their documentation for instructions on how to enable RADIUS Accounting.

## Configure RADIUS Accounting on the VPN system

Perform the following steps on your RRAS server.
 
1.	Open the Routing and Remote Access console.
2.	Right-click the server name and click **Properties**.
3.	In the **Security** tab, under **Accounting provider**, select **RADIUS Accounting** and click **Configure**.

    ![RADIUS setup](./media/radius-setup.png)

4.	In the **Add RADIUS Server** window, type the **Server name** of the closest Azure ATP standalone sensor or Azure ATP sensor. Under **Port**, make sure the default of 1813 is configured. Click **Change** and type a new shared secret string of alphanumeric characters that you can remember. You need to fill it out later in your Azure ATP Configuration. Check the **Send RADIUS Account On and Accounting Off messages** box and then click **OK** on all open dialog boxes.
 
     ![VPN setup](./media/vpn-set-accounting.png)
     
### Configure VPN in ATP

Azure ATP collects VPN data that helps profile the locations from which computers connect to the network and to be able to detect abnormal VPN connections.

To configure VPN data in ATP:

1.	In the Azure ATP workspace portal, click on the configuration cog and then **VPN**.
 

2.	Turn on **Radius Accounting**, and type the **Shared Secret** you configured previously on your RRAS VPN Server. Then click **Save**.
 

  ![Configure Azure ATP VPN](./media/atp-vpn-radius.png)


After this is enabled, all Azure ATP standalone sensors and sensors listen on port 1813 for RADIUS accounting events. 

Your setup is complete, and you can now see VPN activity in the users' profile page:
 
   ![VPN setup](./media/vpn-user.png)

After the Azure ATP Sensor receives the VPN events and sends them to the Azure ATP cloud service for processing, it will be added to the user profile.





>[!div class="step-by-step"]
[« Step 6](install-atp-step5.md)
[Step 7 »](install-atp-step7.md)


## See Also
- [Azure ATP sizing tool](http://aka.ms/aatpsizingtool)
- [Configure event collection](configure-event-collection.md)
- [Azure ATP prerequisites](atp-prerequisites.md)

