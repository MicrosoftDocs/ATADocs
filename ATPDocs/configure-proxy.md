---
# required metadata

title: Configure your proxy or firewall to enable Azure ATP communication with the sensor | Microsoft Docs
description: Describes how to set up your firewall or proxy to allow communication between the Azure ATP cloud service and Azure ATP sensors
keywords:
author: mlottner
ms.author: mlottner
manager: barbkess
ms.date: 03/17/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
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



# Configure endpoint proxy and Internet connectivity settings for your Azure ATP Sensor

Each Azure Advanced Threat Protection (ATP) sensor requires Internet connectivity to the Azure ATP cloud service to operate successfully. In some organizations, the domain controllers aren’t directly connected to the Internet, but are connected through a web proxy connection. Each Azure ATP sensor requires that you use the Microsoft Windows Internet (WinINET) proxy configuration to report sensor data and communicate with the Azure ATP service. If you use WinHTTP for proxy configuration, you still need to configure Windows Internet (WinINet) browser proxy settings for communication between the sensor and the Azure ATP cloud service.


When configuring the proxy, you'll need to know that the embedded Azure ATP sensor service runs in system context using the **LocalService** account and the Azure ATP Sensor Updater service runs in the system context using **LocalSystem** account. 

> [!NOTE]
> If you're using Transparent proxy or WPAD in your network topology, you don't need to configure WinINET for your proxy.

## Configure the proxy 

Configure your proxy server manually using a registry-based static proxy, to allow Azure ATP sensor to report diagnostic data and communicate with Azure ATP cloud service when a computer is not permitted to connect to the Internet.

> [!NOTE]
> The registry changes should be applied only to LocalService and LocalSystem.

The static proxy is configurable through the Registry. You must copy the proxy configuration that you use in user context to the localsystem and localservice. To copy your user context proxy settings:

1.	 Make sure to back up the registry keys before you modify them.

2. In the registry, search for the value `DefaultConnectionSettings` as REG_BINARY under the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings` and copy it.
 
2.	If the LocalSystem does not have the correct proxy settings (either they are not configured or they are different from the Current_User), then copy the proxy setting from the Current_User to the LocalSystem. Under the registry key `HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings`.

3.	Paste the value from the Current_user `DefaultConnectionSettings` as REG_BINARY.

4.	If the LocalService does not have the correct proxy settings, then copy the proxy setting from the Current_User to the LocalService. Under the registry key `HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings`.

5.	Paste the value from the Current_User `DefaultConnectionSettings` as REG_BINARY.

> [!NOTE]
> This will affect all applications including Windows services which use WinINET with LocalService, LocalSytem context.


## Enable access to Azure ATP service URLs in the proxy server

To enable access to Azure ATP allow traffic to the following URLs:

- \<your-instance-name>.atp.azure.com – for console connectivity. For example, "Contoso-corp.atp.azure.com"

- \<your-instance-name>sensorapi.atp.azure.com – for sensors connectivity. For example, "contoso-corpsensorapi.atp.azure.com"

The previous URLs automatically map to the correct service location for your Azure ATP instance. If you require more granular control, consider allowing traffic to the relevant endpoints from the following table:

|Service location|*.atp.azure.com DNS record|
|----|----|
|US	|triprd1wcusw1sensorapi.atp.azure.com<br>triprd1wcuswb1sensorapi.atp.azure.com<br>triprd1wcuse1sensorapi.atp.azure.com|
|Europe|triprd1wceun1sensorapi.atp.azure.com<br>triprd1wceuw1sensorapi.atp.azure.com|
|Asia|triprd1wcasse1sensorapi.atp.azure.com|

 
> [!NOTE]
> When performing SSL inspection on the Azure ATP network traffic (between the sensor and the Azure ATP service), the SSL inspection must support mutual inspection.


## See Also
- [Configure event forwarding](configure-event-forwarding.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
