---
# required metadata

title: Troubleshooting Azure ATP known issues | Microsoft Docs
description: Describes how you can troubleshoot issues in Azure ATP.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 3/6/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 23386e36-2756-4291-923f-fa8607b5518a


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


# Troubleshooting Azure ATP Known Issues 

## Azure ATP sensor NIC teaming issue

If you attempt to install the ATP sensor on a machine configured with a NIC Teaming adapter, you receive an installation error. If you want to install the ATP sensor on a machine configured with NIC teaming, please follow these instructions:

If you did not install the sensor yet:

1.	Download Npcap from [https://nmap.org/npcap/](https://nmap.org/npcap/).
2.	Uninstall WinPcap, if it was installed.
3.	Install Npcap with the following options: loopback_support=no & winpcap_mode=yes
4.	Install the sensor package.

If you already installed the sensor:

1.	Download Npcap from [https://nmap.org/npcap/](https://nmap.org/npcap/).
2.	Uninstall the sensor.
3.	Uninstall WinPcap.
4.	Install Npcap with the following options: loopback_support=no & winpcap_mode=yes
5.	Reinstall the sensor package.

## Windows Defender ATP integration issue

Azure Advanced Threat Protection enables you to integrate Azure ATP with Windows Defender ATP. Integration is currently only enabled if you are a Windows Defender ATP private preview customer. 

## VMware virtual machine sensor issue

If you have an Azure ATP sensor on VMware virtual machines, you might receive the monitoring alert **Some network traffic is not being analyzed**. This happens because of a configuration mismatch in VMware.

To resolve the issue:

Set the following settings to **0** or **Disabled** in the virtual machine's NIC configuration: TsoEnable, LargeSendOffload, TSO Offload, Giant TSO Offload.
> [!NOTE]
> For Azure ATP sensors, you only need to disable **IPv4 TSO Offload** under the NIC configuration.

 ![VMware sensor issue](./media/vm-sensor-issue.png)

## See Also
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)