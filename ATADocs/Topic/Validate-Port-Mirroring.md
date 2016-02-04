---
title: Validate Port Mirroring
ms.custom: 
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology: 
  - security
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: ebd41719-c91a-4fdd-bcab-2affa2a2cace
author: Rkarlin
---
# Validate Port Mirroring
The following steps walk you through the process for validating that port mirroring is properly configured. For ATA to work properly, the ATA Gateway must be able to see the traffic to and from the domain controller. The main data source used by ATA is deep packet inspection of the network traffic to and from your domain controllers. For ATA to see the network traffic, port mirroring needs to be configured. Port mirroring copies the traffic from one port (the source port) to another port (the destination port).

1.  Install [Microsoft Network Monitor 3.4](http://www.microsoft.com/download/details.aspx?id=4865) or another network sniffing tool.

    > [!IMPORTANT]
    > Do not install Microsoft Message Analyzer, or any other traffic capture software on the ATA Gateway.

2.  Open Network Monitor and create a new capture tab.

    1.  Select only the **Capture** network adapter or the network adapter that is connected to the switch port that is configured as the port mirroring destination.

    2.  Ensure that P-Mode is enabled.

    3.  Click **New Capture**.

        ![](../Image/ATA-Port-Mirroring-Capture.jpg)

3.  In the Display Filter window, enter the following filter: **KerberosV5 OR LDAP** and then click **Apply**.

    ![](../Image/ATA-Port-Mirroring-filter-settings.jpg)

4.  Click **Start** to start the capture session. If you do not see traffic to and from the domain controller, review your port mirroring configuration.

    > [!NOTE]
    > It is important to make sure you see traffic to and from the domain controllers.
    > 
    > ![](../Image/ATA-Port-Mirroring-Capture-traffic.jpg)

5.  If you only see traffic in one direction, you should work with your networking or virtualization teams to help troubleshoot your port mirroring configuration.

## See Also
[Configure Port Mirroring](../Topic/Configure-Port-Mirroring.md)
 [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)

