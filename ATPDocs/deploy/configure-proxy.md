---
title: Verify connectivity to the Defender for Identity service | Microsoft Defender for Identity
description: Learn how to set up your firewall or proxy to allow communication between the Microsoft Defender for Identity cloud service and Microsoft Defender for Identity sensors.
ms.date: 02/12/2024
ms.topic: how-to
---

# Configure endpoint proxy and internet connectivity settings

Each Microsoft Defender for Identity sensor requires internet connectivity to the Defender for Identity cloud service to report sensor data and operate successfully.

In some organizations, the domain controllers aren't directly connected to the internet, but are connected through a web proxy connection, and SSL inspection and intercepting proxies are not supported for security reasons. In such cases, your proxy server must allow the data to directly pass from the Defender for Identity sensors to the relevant URLs without interception.

> [!IMPORTANT]
> Microsoft does not provide a proxy server. This article describes how to ensure that the required URLs are accessible via a proxy server that you configure.
>

## Enable access to Defender for Identity service URLs in the proxy server

To ensure maximal security and data privacy, Defender for Identity uses certificate-based, mutual authentication between each Defender for Identity sensor and the Defender for Identity cloud back-end. SSL inspection and interception are not supported, as they interfere in the authentication process.

To enable access to Defender for Identity, make sure to allow traffic to the sensor URL, using the following syntax: `<your-workspace-name>sensorapi.atp.azure.com`. For example, `contoso-corpsensorapi.atp.azure.com`.

- If your proxy or firewall uses explicit allowlists, we also recommend ensuring that the following URLs are allowed:

    - `crl.microsoft.com`
    - `ctldl.windowsupdate.com`
    - `www.microsoft.com/pkiops/*`
    - `www.microsoft.com/pki/*`

- Occasionally, the Defender for Identity service IP addresses may change. If you manually configure IP addresses, or if your proxy automatically resolves DNS names to their IP address and uses them, we recommend that you periodically check that the configured IP addresses are still up-to-date.

- If you've previously configured your proxy using legacy options, including WiniNet or a registry key update, you'll need to make any changes using the method you used originally. For more information, see [Change proxy configuration using legacy methods](#change-proxy-configuration-using-legacy-methods).

### Enable access with a service tag

Instead of manually enabling access to specific endpoints, download the [Azure IP Ranges and Service Tags - Public Cloud](https://www.microsoft.com/download/details.aspx?id=56519), and use the IP address ranges in the **AzureAdvancedThreatProtection** Azure service tag to enable access to Defender for Identity.

For more information, see [Virtual network service tags](/azure/virtual-network/service-tags-overview). For US Government offerings, see [Get started with US Government offerings](../us-govt-gcc-high.md).

## Change proxy configuration using the CLI

**Prerequisites**: Locate the `Microsoft.Tri.Sensor.Deployment.Deployer.exe` file. This file is located together with the sensor installation. By default, this location is `C:\Program Files\Azure Advanced Threat Protection Sensor\version number\`

**To change the current sensor's proxy configuration**:

```cmd
Microsoft.Tri.Sensor.Deployment.Deployer.exe ProxyUrl="http://myproxy.contoso.local" ProxyUserName="CONTOSO\myProxyUser" ProxyUserPassword="myPr0xyPa55w0rd"
```

**To remove the current sensor's proxy configuration entirely**:

```cmd
Microsoft.Tri.Sensor.Deployment.Deployer.exe ClearProxyConfiguration
```

## Change proxy configuration using PowerShell

**Prerequisites**: Before running Defender for Identity PowerShell commands, make sure that you've downloaded the [Defender for Identity PowerShell module](https://www.powershellgallery.com/packages/DefenderForIdentity/).

You can view and change the proxy configuration for your sensor using PowerShell. To do so, sign into your sensor server and run commands as shown in the following examples:

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

For more information, see the following [DefenderForIdentity PowerShell references](/powershell/defenderforidentity/overview-defenderforidentity):

- [Get-MDISensorProxyConfiguration](/powershell/module/defenderforidentity/get-mdisensorproxyconfiguration)
- [Set-MDISensorProxyConfiguration](/powershell/module/defenderforidentity/set-mdisensorproxyconfiguration)
- [Clear-MDISensorProxyConfiguration](/powershell/module/defenderforidentity/clear-mdisensorproxyconfiguration)

## Change proxy configuration using legacy methods

If you'd previously configured your proxy settings via either WinINet or a registry key and need to update them, you'll need to use the same method you used originally.

While configuring your proxy from the command line during installation ensures that only the Defender for Identity sensor services communicate through the proxy, using WinINet or a registry allow other services running in the context as Local System or Local Service to also direct traffic through the proxy.  

### Configure a proxy server using WinINet

When configuring the proxy using WinINet, keep in mind that the embedded Defender for Identity sensor service runs in system context using the **LocalService** account, and that the Defender for Identity Sensor updater service runs in the system context using **LocalSystem** account.

- If you use WinHTTP for proxy configuration, you still need to configure Windows Internet (WinINet) browser proxy settings for communication between the sensor and the Defender for Identity cloud service.

- If you're using Transparent proxy or WPAD in your network topology, you don't need to configure WinINet for your proxy.

### Configure a proxy server using the registry

This section describes how to configure a static proxy server manually using a registry-based static proxy.

> [!IMPORTANT]
> Configuring a proxy via the registry affects all applications that use WinINet with the **LocalService** and **LocalSystem** accounts, including Windows services.
>
> Apply registry changes only to the **LocalService** and **LocalSystem** accounts.
>

To configure your proxy, copy your proxy configuration in user context to the **LocalSystem** and **LocalService** accounts as follows:

1. Back up your registry keys.

1. In the registry, search for the `DefaultConnectionSettings` value as `REG_BINARY`, under the `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings` registry key, and copy it.

1. If the `LocalSystem` doesn't have the correct proxy settings, copy the proxy setting from the `Current_User` to the `LocalSystem`, under the `HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings` registry key.

    Make sure to paste the value from the `Current_User`'s `DefaultConnectionSettings` registry key as `REG_BINARY`.

    This may happen if your proxy settings aren't configured, or if they're different from the `Current_User`.

1. If the `LocalService` doesn't have the correct proxy settings, then copy the proxy setting from the `Current_User` to the `LocalService`, under the `HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings` registry key.

    Make sure to paste the value from the `Current_User`'s `DefaultConnectionSettings` registry key as `REG_BINARY`.

## Test connectivity

The Defender for Identity sensor requires network connectivity to the Defender for Identity service running in Azure. Most organizations control access to the internet via firewall or proxies.  

When using a proxy, you can allow access port 443 via a single URL. For more information, see [Required ports](prerequisites.md#required-ports).

Do the following steps to confirm that everything is working as expected. Perform this procedure either before you deploy the sensor, or if the sensor experiences connectivity issues after being installed.

**To test your connectivity settings**:

1. Open a browser. If you're using a proxy, make sure that your browser uses the same proxy settings being used by the sensor.

    For example, if the proxy settings are defined for **Local System**, you'll need to use PSExec to open a session as **Local System** and open the browser from that session.

1. Browse to the following URL: `https://<your_workspace_name>sensorapi.atp.azure.com/tri/sensor/api/ping.` Replace `<your_workspace_name>` with the name of your Defender for Identity workspace.

    > [!IMPORTANT]
    > You *must* specify `HTTPS`, not `HTTP`, to properly test connectivity.

**Result**: You should get an *Ok* message displayed (HTTP status 200), which indicates you were successfully able to route to the Defender for Identity HTTPS endpoint. This is the desired result. 

For some older workspaces, the message returned could be *Error 503 The service is unavailable*. This is a temporary state that still indicates success. For example:

:::image type="content" source="../media/configure-proxy/test-proxy.png" alt-text="Screenshot of an HTTP 200 status code (OK).":::

- If you don't get *Ok* message, then you may have a problem with your proxy configuration. Check your network and proxy settings.

- If you get a certificate error, ensure that you have the required trusted root certificates installed before continuing. For more information, see [Proxy authentication problem presents as a connection error](../troubleshooting-known-issues.md#proxy-authentication-problem-presents-as-a-connection-error). The certificate details should look like this: 

    :::image type="content" source="../media/configure-proxy/certificate.png" alt-text="Screenshot of the required certificate path.":::

## Related content

For more information, see:

- [Run a silent installation with a proxy configuration](install-sensor.md#run-a-silent-installation-with-a-proxy-configuration)
- [Test Microsoft Defender for Identity connectivity](test-connectivity.md)

## Next step

> [!div class="step-by-step"]
> [Test Microsoft Defender for Identity connectivity »](test-connectivity.md)
