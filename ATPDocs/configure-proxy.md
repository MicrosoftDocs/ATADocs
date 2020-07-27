---
# required metadata

title: Configure your proxy or firewall to enable Azure ATP communication with the sensor
description: Describes how to set up your firewall or proxy to allow communication between the Azure ATP cloud service and Azure ATP sensors
keywords:
author: shsagir
ms.author: shsagir
manager: shsagir
ms.date: 07/05/2020
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

Each Azure Advanced Threat Protection (ATP) sensor requires Internet connectivity to the Azure ATP cloud service to report sensor data and operate successfully. In some organizations, the domain controllers aren't directly connected to the internet, but are connected through a web proxy connection.

We recommend using the command line to configure your proxy server.

## Configure proxy server using the command line

You can configure your proxy server during sensor installation using the following command line switches.

### Syntax

"Azure ATP sensor Setup.exe" [/quiet] [/Help] [ProxyUrl="<Proxy URL>"] [ProxyUserName="<Username>"] [ProxyUserPassword="<Password>"]

### Switch descriptions

> [!div class="mx-tableFixed"]
>
> |Name|Syntax|Mandatory for silent installation?|Description|
> |-------------|----------|---------|---------|
> |ProxyUrl|ProxyUrl="http\://proxy.contoso.com:8080"|No|Specifies the ProxyUrl and port number for the Azure ATP sensor.|
> |ProxyUserName|ProxyUserName="Contoso\ProxyUser"|No|If your proxy service requires authentication, supply a user name in the DOMAIN\user format.|
> |ProxyUserPassword|ProxyUserPassword="P@ssw0rd"|No|Specifies the password for proxy user name. *Credentials are encrypted and stored locally by the Azure ATP sensor.|

## Alternative methods to configure your proxy server

You can use one of the following alternative methods to configure your proxy server.

- [Configure proxy server using WinINet](#configure-proxy-server-using-wininet)
- [Configure proxy server using the registry](#configure-proxy-server-using-the-registry)

### Configure proxy server using WinINet

You can configure your proxy server using Microsoft Windows Internet (WinINet) proxy configuration, to allow Azure ATP sensor to report diagnostic data and communicate with Azure ATP cloud service when a computer is not permitted to connect to the Internet. If you use WinHTTP for proxy configuration, you still need to configure Windows Internet (WinINet) browser proxy settings for communication between the sensor and the Azure ATP cloud service.

When configuring the proxy, remember that the embedded Azure ATP sensor service runs in system context using the **LocalService** account, and that the Azure ATP Sensor Updater service runs in the system context using **LocalSystem** account.

> [!NOTE]
> If you're using Transparent proxy or WPAD in your network topology, you don't need to configure WinINet for your proxy.

### Configure proxy server using the registry

You can also configure your proxy server manually using a registry-based static proxy, to allow Azure ATP sensor to report diagnostic data and communicate with Azure ATP cloud service when a computer is not permitted to connect to the Internet.

> [!NOTE]
> The registry changes should be applied only to LocalService and LocalSystem.

The static proxy is configurable through the Registry. You must copy the proxy configuration that you use in user context to the localsystem and localservice. To copy your user context proxy settings:

1. Make sure to back up the registry keys before you modify them.

1. In the registry, search for the value `DefaultConnectionSettings` as REG_BINARY under the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings` and copy it.

1. If the LocalSystem does not have the correct proxy settings (either they are not configured or they are different from the Current_User), then copy the proxy setting from the Current_User to the LocalSystem. Under the registry key `HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings`.

1. Paste the value from the Current_user `DefaultConnectionSettings` as REG_BINARY.

1. If the LocalService does not have the correct proxy settings, then copy the proxy setting from the Current_User to the LocalService. Under the registry key `HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings`.

1. Paste the value from the Current_User `DefaultConnectionSettings` as REG_BINARY.

> [!NOTE]
> This will affect all applications including Windows services which use WinINET with LocalService, LocalSytem context.

## Enable access to Azure ATP service URLs in the proxy server

To enable access to Azure ATP, we recommend allowing traffic to the following URLs. The URLs automatically map to the correct service location for your Azure ATP instance.

- `<your-instance-name>.atp.azure.com` – for console connectivity. For example, "contoso-corp.atp.azure.com"

- `<your-instance-name>sensorapi.atp.azure.com` – for sensors connectivity. For example, "contoso-corpsensorapi.atp.azure.com"

You can also use the IP address ranges in our Azure service tag (**AzureAdvancedThreatProtection**) to enable access to Azure ATP. For more information about service tags, see [Virtual network service tags](https://docs.microsoft.com/azure/virtual-network/service-tags-overview) or [download the service tags](https://www.microsoft.com/download/details.aspx?id=56519) file.

Alternatively, if you require more granular control, consider allowing traffic to the relevant endpoints from the following table:

|Service location|*.atp.azure.com DNS record|
|----|----|
|US |triprd1wcusw2sensorapi.atp.azure.com<br>triprd1wcuswb3sensorapi.atp.azure.com<br>triprd1wcuse3sensorapi.atp.azure.com|
|Europe|triprd1wceun2sensorapi.atp.azure.com<br>triprd1wceuw3sensorapi.atp.azure.com|
|Asia|triprd1wcasse2sensorapi.atp.azure.com|
|UK|triprd1wcuks2sensorapi.atp.azure.com|

> [!NOTE]
>
> - To ensure maximal security and data privacy, Azure ATP uses certificate based mutual authentication between each Azure ATP sensor and the Azure ATP cloud backend. If SSL inspection is used in your environment, make sure that the inspection is configured for mutual authentication so it does not interfere in the authentication process.
> - Occasionally, the Azure ATP service IP addresses may change. Therefore, if you manually configure IP addresses or if your proxy automatically resolves DNS names to their IP address and uses them, you should periodically check that the configured IP addresses are still up-to-date.

## See Also

- [Configure event forwarding](configure-event-forwarding.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
