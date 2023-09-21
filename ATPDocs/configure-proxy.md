---
title: Configure endpoint proxy and Internet connectivity settings
description: Describes how to set up your firewall or proxy to allow communication between the Microsoft Defender for Identity cloud service and Microsoft Defender for Identity sensors
ms.date: 04/16/2023
ms.topic: how-to
---

# Configure endpoint proxy and Internet connectivity settings for your Microsoft Defender for Identity sensor

Each Microsoft Defender for Identity sensor requires Internet connectivity to the Defender for Identity cloud service to report sensor data and operate successfully. In some organizations, the domain controllers aren't directly connected to the internet, but are connected through a web proxy connection. SSL inspection and intercepting proxies are not supported for security reasons. Your proxy server should allow the data to directly pass from the Defender for Identity sensors to the relevant URLs without interception.

<!--i moved this location to after installation. do this in the deploy PR too.-->
> [!NOTE]
> Microsoft does not provide a proxy server. The URLs will be accessible via the proxy server that you configure.

## Configure proxy server using the command line

Use the following command to configure your proxy server settings and install the Defender for Identity sensor together. 

You can configure your proxy server during sensor installation using the following command-line switches.

### Syntax

"Azure ATP sensor Setup.exe" [/quiet] [/Help] [ProxyUrl="http://proxy.internal.com"] [ProxyUserName="domain\proxyuser"] [ProxyUserPassword="ProxyPassword"]

### Switch descriptions

> [!div class="mx-tableFixed"]
>
> |Name|Syntax|Mandatory for silent installation?|Description|
> |-------------|----------|---------|---------|
> |ProxyUrl|ProxyUrl="http\://proxy.contoso.com:8080"|No|Specifies the ProxyUrl and port number for the Defender for Identity sensor.|
> |ProxyUserName|ProxyUserName="Contoso\ProxyUser"|No|If your proxy service requires authentication, supply a user name in the DOMAIN\user format.|
> |ProxyUserPassword|ProxyUserPassword="P@ssw0rd"|No|Specifies the password for proxy user name. *Credentials are encrypted and stored locally by the Defender for Identity sensor.|

To change the proxy configuration, see <xref to powershell>.

## Change proxy configuration using PowerShell

You can view and change the proxy configuration for your sensor using PowerShell. To do so, sign into your sensor server and run commands as shown in the following examples:

<!--we need notes that you need to install the powershell module-->

**To view the current sensor's proxy configuration**:

```powershell
Get-MDISensorProxyConfiguration
```

**To change the current sensor's proxy configuration**:

```powershell
Set-MDISensorProxyConfiguration -ProxyUrl 'http://proxy.contoso.com:8080'
```

This example sets the proxy configuration for the Defender for Identity sensor to use the specified proxy server without any credentials.


**To remove the current sensor's proxy configuration entirely**:

```powershell
Clear-MDISensorProxyConfiguration
```

For more information, see <xref>.

## Alternative methods to configure your proxy server

<!--if you've used these to start, you need to go on with them. we can switch this from alt to legacy-->

You can use one of the following alternative methods to configure your proxy server. When configuring the proxy settings using these methods, other services running in the context as Local System or Local Service will also direct traffic through the proxy.

- [Configure proxy server using WinINet](#configure-proxy-server-using-wininet)
- [Configure proxy server using the registry](#configure-proxy-server-using-the-registry)

### Configure proxy server using WinINet

You can configure your proxy server using Microsoft Windows Internet (WinINet) proxy configuration, to allow Defender for Identity sensor to report diagnostic data and communicate with Defender for Identity cloud service when a computer isn't permitted to connect to the Internet. If you use WinHTTP for proxy configuration, you still need to configure Windows Internet (WinINet) browser proxy settings for communication between the sensor and the Defender for Identity cloud service.

When configuring the proxy, remember that the embedded Defender for Identity sensor service runs in system context using the **LocalService** account, and that the Defender for Identity Sensor Updater service runs in the system context using **LocalSystem** account.

> [!NOTE]
> If you're using Transparent proxy or WPAD in your network topology, you don't need to configure WinINet for your proxy.

### Configure proxy server using the registry

You can also configure your proxy server manually using a registry-based static proxy, to allow Defender for Identity sensor to report diagnostic data and communicate with Defender for Identity cloud service when a computer isn't permitted to connect to the Internet.

> [!NOTE]
> The registry changes should be applied only to LocalService and LocalSystem.

The static proxy is configurable through the Registry. You must copy the proxy configuration that you use in user context to the LocalSystem and LocalService. To copy your user context proxy settings:

1. Make sure to back up the registry keys before you modify them.

1. In the registry, search for the value `DefaultConnectionSettings` as REG_BINARY under the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings` and copy it.

1. If the LocalSystem doesn't have the correct proxy settings (either they aren't configured or they're different from the Current_User), then copy the proxy setting from the Current_User to the LocalSystem. Under the registry key `HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings`.

1. Paste the value from the Current_user `DefaultConnectionSettings` as REG_BINARY.

1. If the LocalService doesn't have the correct proxy settings, then copy the proxy setting from the Current_User to the LocalService. Under the registry key `HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings`.

1. Paste the value from the Current_User `DefaultConnectionSettings` as REG_BINARY.

> [!NOTE]
> This will affect all applications including Windows services which use WinINET with LocalService, LocalSytem context.

## Enable access to Defender for Identity service URLs in the proxy server

To enable access to Defender for Identity, we require allowing traffic to the following URLs. The URLs automatically map to the correct service location for your Defender for Identity instance.

- `<your-instance-name>sensorapi.atp.azure.com` - for example, `contoso-corpsensorapi.atp.azure.com`

You can also use the IP address ranges in our Azure service tag (**AzureAdvancedThreatProtection**) to enable access to Defender for Identity. For more information about service tags, see [Virtual network service tags](/azure/virtual-network/service-tags-overview).

If you would like to download the "Azure IP Ranges and Service Tags - Public Cloud" file, you can do so [here](https://www.microsoft.com/download/details.aspx?id=56519). For US Government offerings, see [Get started with US Government offerings](us-govt-gcc-high.md).

> [!NOTE]
>
> - To ensure maximal security and data privacy, Defender for Identity uses certificate based mutual authentication between each Defender for Identity sensor and the Defender for Identity cloud backend. SSL inspection and interception are not supported, as they interfere in the authentication process.
> - Occasionally, the Defender for Identity service IP addresses may change. Therefore, if you manually configure IP addresses or if your proxy automatically resolves DNS names to their IP address and uses them, you should periodically check that the configured IP addresses are still up-to-date.


## Next step

> [!div class="step-by-step"]
> [« Download the Defender for Identity sensor](download-sensor.md)
> [Install the Defender for Identity sensor »](install-sensor.md)
> [Test Microsoft Defender for Identity connectivity »](deploy/test-connectivity.md)