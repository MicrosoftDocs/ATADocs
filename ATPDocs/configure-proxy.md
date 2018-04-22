---
# required metadata

title: Configure your proxy or firewall to enable Azure ATP communication with the sensor | Microsoft Docs
description: Describes how to set up your firewall or proxy to allow communication between the Azure ATP cloud service and Azure ATP sensors
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 4/22/2018
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 9c173d28-a944-491a-92c1-9690eb06b151

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



# Configure endpoint proxy and Internet connectivity settings for your Azure ATP Sensor

Each Azure Advanced Threat Protection (ATP) sensor requires Internet connectivity to the Azure ATP cloud service to operate successfully. In some organizations, the domain controllers aren’t directly connected to the Internet, but are connected through a web proxy connection. Each Azure ATP sensor requires that you use the Microsoft Windows Internet (WinINET) proxy conifguration to report sensor data and communicate with the Azure ATP service. If you use WinHTTP for proxy configuration, you still need to configure Windows Internet (WinINet) brower proxy settings for communication between the sensor and the Azure ATP cloud service.


When configuring the proxy, you will need to know that the embedded Azure ATP sensor service runs in system context using the **LocalService** account and the Azure ATP Sensor Updater service runs in the system context using **LocalSystem** account. 

> [!NOTE]
> If you're using Transparent proxy or WPAD in your network topology, you do not need to configure WinINET for your proxy.

## Configure the proxy 

Configure your proxy server manually using a registry-based static proxy, to allow Azure ATP sensor to report diagnostic data and communicate with Azure ATP cloud service when a computer is not permitted to connect to the Internet.

> [!NOTE]
> The registry changes should be applied only to LocalService and LocalSystem.

The static proxy is configurable through the Registry. You must copy the proxy configuration that you use in user context to the localsystem and localservice. To copy your user context proxy settings:

1.	 Make sure to back up the registry keys before you modify them.

2. In the registry, search for the value `DefaultConnectionSetting` as REG_BINARY under the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\InternetSetting\Connections\DefaultConnectionSetting` and copy it.
 
2.	If the LocalSystem does not have the correct proxy settings (either they are not configured or they are different from the Current_User), then copy the proxy setting from the Current_User to the LocalSystem. Under the registry key `HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\InternetSetting\Connections\DefaultConnectionSetting`.

3.	Paste the value from the Current_user `DefaultConnectionSetting` as REG_BINARY.

4.	If the LocalService does not have the correct proxy settings, then copy the proxy setting from the Current_User to the LocalService. Under the registry key `HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\InternetSetting\Connections\DefaultConnectionSetting`.

5.	Paste the value from the Current_User `DefaultConnectionSetting` as REG_BINARY.

> [!NOTE]
> This will affect all applications including Windows services which use WinINET with LocalService, LocalSytem context.


## Enable access to Azure ATP service URLs in the proxy server

If a proxy or firewall is blocking all traffic by default and allowing only specific domains through or HTTPS scanning (SSL inspection) is enabled, make sure that the following URLs are white-listed to permit communication with the Azure ATP service in port 443:

|Service location|.Atp.Azure.com DNS record|
|----|----|
|US	|triprd1wcusw1sensorapi.atp.azure.com<br>triprd1wcuswb1sensorapi.atp.azure.com<br>triprd1wcuse1sensorapi.atp.azure.com|
|Europe|triprd1wceun1sensorapi.atp.azure.com<br>triprd1wceuw1sensorapi.atp.azure.com|
|Asia|triprd1wcasse1sensorapi.atp.azure.com|

> [!NOTE]
> When performing SSL inspection on the Azure ATP network traffic (between the sensor and the Azure ATP service), the SSL inspection must support mutual inspection.


## See Also
- [Configure event forwarding](configure-event-forwarding.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)