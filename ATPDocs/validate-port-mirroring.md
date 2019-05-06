---
# required metadata

title: Validate port mirroring in Azure Advanced Threat Protection | Microsoft Docs
description: Describes how to validate that port mirroring is configured correctly in Azure ATP
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 10/04/2018
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 0a56cf27-9eaa-4ad0-ae6c-9d0484c69094

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---



# Validate Port Mirroring
> [!NOTE] 
> This article is relevant only if you deploy deploy Azure ATP Standalone Sensor instead of Azure ATP Sensor. To determine if you need to use Azure ATP Sensor, see [Choosing the right sensor for your deployment](atp-capacity-planning.md#choosing-the-right-sensor-type-for-your-deployment).
 
The following steps walk you through the process for validating that port mirroring is properly configured. For Azure ATP to work properly, the Azure ATP standalone sensor must be able to see the traffic to and from the domain controller. The main data source used by Azure ATP is deep packet inspection of the network traffic to and from your domain controllers. For Azure ATP to see the network traffic, port mirroring needs to be configured. Port mirroring copies the traffic from one port (the source port) to another port (the destination port).

## Validate port mirroring using Net Mon
1.  Install [Microsoft Network Monitor 3.4](http://www.microsoft.com/download/details.aspx?id=4865) on the ATP standalone sensor that you want to validate.

    > [!IMPORTANT]
    > If you choose to install Wireshark in order to validate port mirroring, restart the Azure ATP standalone sensor service after validation.

2.  Open Network Monitor and create a new capture tab.

    1.  Select only the **Capture** network adapter or the network adapter that is connected to the switch port that is configured as the port mirroring destination.

    2.  Ensure that P-Mode is enabled.

    3.  Click **New Capture**.

        ![Create new capture tab image](media/atp-port-mirroring-capture.png)

3.  In the Display Filter window, enter the following filter: **KerberosV5 OR LDAP** and then click **Apply**.

    ![Apply KerberosV5 or LDAP filter image](media/atp-port-mirroring-filter-settings.png)

4.  Click **Start** to start the capture session. If you do not see traffic to and from the domain controller, review your port mirroring configuration.

    ![Start capture session image](media/atp-port-mirroring-capture-traffic.png)

    > [!NOTE]
    > It is important to make sure you see traffic to and from the domain controllers.
    

5.  If you only see traffic in one direction, work with your networking or virtualization teams to help troubleshoot your port mirroring configuration.

## See Also

- [Configure event forwarding](configure-event-forwarding.md)
- [Configure port mirroring](configure-port-mirroring.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
