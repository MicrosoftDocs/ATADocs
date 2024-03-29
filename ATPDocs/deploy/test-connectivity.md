---
title: Test connectivity | Microsoft Defender for Identity
description: Learn how to test whether the server where you're installing your Microsoft Defender for Identity sensor can access the Defender for Identity cloud service.
ms.date: 01/16/2024
ms.topic: how-to
#CustomerIntent: As a Defender for Identity admin, I want to verify that the server I'm using for my sensor can connect successfully to the Defender for Identity cloud service so that I can continue on with deploying confidently.
---

# Test Microsoft Defender for Identity connectivity

The Defender for Identity sensor requires network connectivity to the Defender for Identity service, and most organizations control access to the internet via firewall or proxies.

After preparing the server that you're going to use for your Microsoft Defender for Identity sensor and configuring proxy settings as needed, we recommend that you test connectivity to make sure that your server can access the Defender for Identity cloud service. Use the procedures in this article even after deploying if your sensor server is experiencing connectivity issues.

For more information, see [Required ports](../prerequisites.md#ports).

## Test connectivity using a browser

1. Open a browser using the same settings, including proxy settings, as you're using with the sensor server.

    >[!NOTE]
    >If your proxy settings are defined for **Local System**, you'll need to use PSExec to open a session as **Local System** and open the browser from that session.

1. Browse to the following URL: `https://<your_workspace_name>sensorapi.atp.azure.com/tri/sensor/api/ping`. Replace `<your_workspace_name>` with the name of your Defender for Identity workspace.

    >[!IMPORTANT]
    >You must specify HTTPS, not HTTP, to properly test connectivity.

1. **Result**: You should get a page with the text *Ok*, which indicates you were successfully able to route to the Defender for Identity HTTPS endpoint.  This message is the desired result.

    If you don't get *Ok*, then you might have a problem with your proxy configuration. Check your network and proxy settings.
   
1. If you get a certificate error, ensure that you have the required trusted root certificates installed before continuing. For more information, see [Proxy authentication problem presents as a connection error](../troubleshooting-known-issues.md#proxy-authentication-problem-presents-as-a-connection-error). The certificate details should look like this:

    :::image type="content" source="../media/configure-proxy/certificate.png" alt-text="Screenshot of a certificate path.":::
    
### Test service connectivity using PowerShell

**Prerequisites**: Before running Defender for Identity PowerShell commands, make sure that you downloaded the [Defender for Identity PowerShell module](https://www.powershellgallery.com/packages/DefenderForIdentity/).

Sign into your server and run one of the following commands:

- To use the current server's settings, run:

    ```powershell
    Test-MDISensorApiConnection
    ```

- To test settings that you're planning on using, but aren't currently configured on the server, run the command using the following syntax:

    ```powershell
    Test-MDISensorApiConnection -BypassConfiguration -SensorApiUrl 'https://contososensorapi.atp.azure.com' -ProxyUrl 'https://myproxy.contoso.com:8080' -ProxyCredential $credential
    ```

    Where:
    
    - `https://contososensorapi.atp.azure.com` is an example of your sensor URL, where *contososensor* is the name of your workspace.
    - `https://myproxy.contoso.com:8080` is an example of your proxy URL

For more information, see the [MDI PowerShell documentation](/powershell/module/defenderforidentity/test-mdisensorapiconnection).

## Next step


> [!div class="step-by-step"]
> [Download the Microsoft Defender for Identity sensor »](download-sensor.md)
