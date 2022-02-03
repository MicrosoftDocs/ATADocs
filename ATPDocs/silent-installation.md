---
title: Install Microsoft Defender for Identity Silently
description: This describes how to silently install Microsoft Defender for Identity.
ms.date: 01/11/2021
ms.topic: how-to
---

# Microsoft Defender for Identity switches and silent installation

This article provides guidance and instructions for [!INCLUDE [Product long](includes/product-long.md)] switches and silent installation.

## Prerequisites

[!INCLUDE [Product short](includes/product-short.md)] requires the installation of Microsoft .NET Framework 4.7 or later.

When you install [!INCLUDE [Product short](includes/product-short.md)], .Net Framework 4.7 is automatically installed as part of the deployment of [!INCLUDE [Product short](includes/product-short.md)] if .Net Framework 4.7 or later is not installed already.

> [!NOTE]
> The installation of .Net framework 4.7 may require rebooting the server. When installing the [!INCLUDE [Product short](includes/product-short.md)] sensor on domain controllers, consider scheduling a maintenance window for the domain controllers.

Using [!INCLUDE [Product short](includes/product-short.md)] silent installation, the installer is configured to automatically restart the server at the end of the installation (if necessary). Make sure to run silent installation only during a maintenance window. Because of a Windows Installer bug, the *norestart* flag cannot be reliably used to make sure the server does not restart.

To track your deployment progress, monitor the [!INCLUDE [Product short](includes/product-short.md)] installer logs, which are located in `%AppData%\Local\Temp`.

## Defender for Identity sensor silent installation

> [!NOTE]
> When silently deploying the [!INCLUDE [Product short](includes/product-short.md)] sensor via System Center Configuration Manager or other software deployment system, it is recommended to create two deployment packages:</br>- Net Framework 4.7 or later which may include rebooting the domain controller</br>- [!INCLUDE [Product short](includes/product-short.md)] sensor. </br>Make the [!INCLUDE [Product short](includes/product-short.md)] sensor package dependent on the deployment of the .Net Framework package deployment. </br>Get the [.Net Framework 4.7 offline deployment package](https://support.microsoft.com/topic/the-net-framework-4-7-offline-installer-for-windows-f32bcb33-5f94-57ce-6120-62c9526a91f2).

Use the following command to perform a fully silent install of the [!INCLUDE [Product short](includes/product-short.md)] sensor:

**cmd.exe syntax**:

```cmd
"Azure ATP sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" AccessKey="<Access Key>"
```

**Powershell syntax**:

```powershell
.\"Azure ATP sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" AccessKey="<Access Key>"
```

> [!NOTE]
> When using the Powershell syntax, omitting the `.\` preface results in an error that prevents silent installation.

> [!NOTE]
> Copy the access key from the [!INCLUDE [Product short](includes/product-short.md)] portal **Configuration** section, **Sensors** page.

**Installation options**:

> [!div class="mx-tableFixed"]
>
> |Name|Syntax|Mandatory for silent installation?|Description|
> |-------------|----------|---------|---------|
> |Quiet|/quiet|Yes|Runs the installer displaying no UI and no prompts.|
> |Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|
> |NetFrameworkCommandLineArguments="/q"|NetFrameworkCommandLineArguments="/q"|Yes|Specifies the parameters for the .Net Framework installation. Must be set to enforce the silent installation of .Net Framework.|

**Installation parameters**:

> [!div class="mx-tableFixed"]
>
> |Name|Syntax|Mandatory for silent installation?|Description|
> |-------------|----------|---------|---------|
> |InstallationPath|InstallationPath=""|No|Sets the path for the installation of [!INCLUDE [Product short](includes/product-short.md)] Sensor binaries. Default path: %programfiles%\Azure Advanced Threat Protection sensor
> |AccessKey|AccessKey="\*\*"|Yes|Sets the access key that is used to register the [!INCLUDE [Product short](includes/product-short.md)] sensor with the [!INCLUDE [Product short](includes/product-short.md)] instance.|

**Examples**:

Use the following command to silently install the [!INCLUDE [Product short](includes/product-short.md)] sensor:

```cmd
"Azure ATP sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" AccessKey="mmAOkLYCzfH8L/zUIsH24BIJBevlAWu7wUcSfIkRJufpuEojaDHYdjrNs0P3zpD+/bObKfLS0puD7biT5KDf3g=="
```

## Proxy authentication

Use the following commands to complete proxy authentication:

**Syntax**:

> [!div class="mx-tableFixed"]
>
> |Name|Syntax|Mandatory for silent installation?|Description|
> |-------------|----------|---------|---------|
> |ProxyUrl|ProxyUrl="http\://proxy.contoso.com:8080"|No|Specifies the ProxyUrl and port number for the [!INCLUDE [Product short](includes/product-short.md)] sensor.|
> |ProxyUserName|ProxyUserName="Contoso\ProxyUser"|No|If your proxy service requires authentication, supply a user name in the DOMAIN\user format.|
> |ProxyUserPassword|ProxyUserPassword="P@ssw0rd"|No|Specifies the password for proxy user name. *Credentials are encrypted and stored locally by the [!INCLUDE [Product short](includes/product-short.md)] sensor.|

For more information about proxy configuration, see [Configure endpoint proxy and Internet connectivity settings for your [!INCLUDE [Product long](includes/product-long.md)] Sensor](configure-proxy.md).

## Update the Defender for Identity sensor

Use the following command to silently update the [!INCLUDE [Product short](includes/product-short.md)] sensor:

**Syntax**:

```cmd
"Azure ATP sensor Setup.exe" [/quiet] [/Help] [NetFrameworkCommandLineArguments="/q"]
```

**Installation options**:

> [!div class="mx-tableFixed"]
>
> |Name|Syntax|Mandatory for silent installation?|Description|
> |-------------|----------|---------|---------|
> |Quiet|/quiet|Yes|Runs the installer displaying no UI and no prompts.|
> |Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|
> |NetFrameworkCommandLineArguments="/q"|NetFrameworkCommandLineArguments="/q"|Yes|Specifies the parameters for the .Net Framework installation. Must be set to enforce the silent installation of .Net Framework.|

**Examples**:

To update the [!INCLUDE [Product short](includes/product-short.md)] sensor silently:

```cmd
"Azure ATP sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q"
```

<a name="silently-uninstall-sensor"></a>

## Uninstall the Defender for Identity sensor silently

Use the following command to perform a silent uninstall of the [!INCLUDE [Product short](includes/product-short.md)] sensor:

**Syntax**:

```cmd
"Azure ATP sensor Setup.exe" [/quiet] [/Uninstall] [/Help]
```

**Installation options**:

> [!div class="mx-tableFixed"]
>
> |Name|Syntax|Mandatory for silent uninstallation?|Description|
> |-------------|----------|---------|---------|
> |Quiet|/quiet|Yes|Runs the uninstaller displaying no UI and no prompts.|
> |Uninstall|/uninstall|Yes|Runs the silent uninstallation of the [!INCLUDE [Product short](includes/product-short.md)] sensor from the server.|
> |Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|

**Examples**:

To silently uninstall the [!INCLUDE [Product short](includes/product-short.md)] sensor from the server:

```cmd
"Azure ATP sensor Setup.exe" /quiet /uninstall
```

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md)
- [Install the [!INCLUDE [Product short](includes/product-short.md)] sensor](install-step4.md)
- [Configure the [!INCLUDE [Product short](includes/product-short.md)] sensor](install-step5.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
