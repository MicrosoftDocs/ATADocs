---
title: Configure endpoint proxy and internet connectivity settings | Microsoft Defender for Identity
description: Learn how to set up your firewall or proxy to allow communication between the Microsoft Defender for Identity cloud service and Microsoft Defender for Identity sensors.
ms.date: 06/13/2023
ms.topic: how-to
---

# Configure endpoint proxy and internet connectivity settings

Each Microsoft Defender for Identity sensor requires internet connectivity to the Defender for Identity cloud service to report sensor data and operate successfully. 

In some organizations, the domain controllers aren't directly connected to the internet, but are connected through a web proxy connection, and SSL inspection and intercepting proxies are not supported for security reasons. In such cases, your proxy server must allow the data to directly pass from the Defender for Identity sensors to the relevant URLs without interception.

If you're using a proxy, we recommend that you configure your proxy together with the sensor installation using command line switches.

If you've previously configured your proxy using legacy options, including WiniNet or a registry key update, you'll need to make any changes using the method you used originally. For more information, see [Configure proxy settings (legacy methods)](../sensor-settings.md#configure-proxy-settings-legacy-methods).

> [!IMPORTANT]
> Microsoft does not provide a proxy server. This article describes how to ensure that the required URLs are accessible via a proxy server that you configure.
>
## Prerequisites

Before starting, make sure that you understand that you want to use a proxy connection instead of option connectivity options. For more information, see [Connectivity requirements](prerequisites.md#connectivity-requirements).

## Configure a proxy server using the command line

Configure your proxy server during sensor installation using the following command-line switches:

### Syntax

`"Azure ATP sensor Setup.exe" [/quiet] [/Help] [ProxyUrl="http://proxy.internal.com"] [ProxyUserName="domain\proxyuser"] [ProxyUserPassword="ProxyPassword"]`

### Switch descriptions

|Name|Syntax|Mandatory for silent installation?|Description|
|-------------|----------|---------|---------|
|**ProxyUrl**|`ProxyUrl="http\://proxy.contoso.com:8080"`|No|Specifies the proxy URL and port number for the Defender for Identity sensor.|
|**ProxyUserName**|`ProxyUserName="Contoso\ProxyUser"`|No|If your proxy service requires authentication, define a user name in the `DOMAIN\user` format.|
|**ProxyUserPassword**|`ProxyUserPassword="P@ssw0rd"`|No|Specifies the password for your  proxy user name. <br><br>Credentials are encrypted and stored locally by the Defender for Identity sensor.|

> [!TIP]
> If you've configured a proxy during installation, changing the proxy configuration requires you to remove and install the sensor. Therefore, we recommend creating and using a custom DNS A record for the proxy server, which you can use to change the proxy server's address when needed. <!--add powershell script in here when ready. also Can mention that to modify the Proxy URL - the cusotmer can modify the sensorconfiguratio.json file manually and stop and restart the sensor services? -->
>
> We also recommend using the *hosts* file for testing.


## Enable access to Defender for Identity service URLs in the proxy server

To ensure maximal security and data privacy, Defender for Identity uses certificate-based, mutual authentication between each Defender for Identity sensor and the Defender for Identity cloud back-end. SSL inspection and interception are not supported, as they interfere in the authentication process.

To enable access to Defender for Identity, make sure to allow traffic to the sensor URL, using the following syntax: `<your-workspace-name>sensorapi.atp.azure.com`. For example, `contoso-corpsensorapi.atp.azure.com`.


The URL syntaxes listed in the table above automatically map to the correct service location for your Defender for Identity workspace.

> [!TIP]
> Occasionally, the Defender for Identity service IP addresses may change. 
>
> If you manually configure IP addresses, or if your proxy automatically resolves DNS names to their IP address and uses them, we recommend that you periodically check that the configured IP addresses are still up-to-date.
>

### Enable access with a service tag

Instead of manually enabling access to specific endpoints, download the [Azure IP Ranges and Service Tags - Public Cloud](https://www.microsoft.com/download/details.aspx?id=56519), and use the IP address ranges in the **AzureAdvancedThreatProtection** Azure service tag to enable access to Defender for Identity. 

For more information, see [Virtual network service tags](/azure/virtual-network/service-tags-overview). 

For US Government offerings, see [Get started with US Government offerings](../us-govt-gcc-high.md).

## Test connectivity

The Defender for Identity sensor requires network connectivity to the Defender for Identity service running in Azure. Most organizations control access to the internet via firewall or proxies.  

When using a proxy, you can allow access port 443 via a single URL. For more information, see [Required ports](prerequisites.md#required-ports)

Do the following steps to confirm that everything is working as expected. Perform this procedure either before you deploy the sensor, or if the sensor experiences connectivity issues after being installed.

**To test your connectivity settings**:

1. Open a browser. 

    If you're using a proxy, make sure that your browser uses the same proxy settings being used by the sensor. For example, if the proxy settings are defined for **Local System**, you'll need to use PSExec to open a session as **Local System** and open the browser from that session.

1. Go to: `https://<your_workspace_name>sensorapi.atp.azure.com`, where `<your_workspace_name>` is the name of your Defender for Identity workspace.

    > [!IMPORTANT]
    > You *must* specify `HTTPS`, not `HTTP`, to properly test connectivity.

You should get an *Error 503 The service is unavailable* message, which indicates you were successfully able to route to the Defender for Identity HTTPS endpoint.  This is the desired result.

If you don't get an *Error 503 The service is unavailable* message, you may have a problem with your connectivity configuration. Check your network and proxy settings.

If you get a certificate error, ensure that you have the required trusted root certificates installed before continuing. For more information, see [Proxy authentication problem presents as a connection error](../troubleshooting-known-issues.md#proxy-authentication-problem-presents-as-a-connection-error). 

Certificate details should look similar to the following: **DigiCert Global Root G2** > **Microsoft Azure TLS Issuing CA 01** > ***.atp.azure.com**.

## Next step

> [!div class="step-by-step"]
> [Install the Defender for Identity sensor »](install-sensor.md)
