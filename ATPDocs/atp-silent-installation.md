---
# required metadata

title: Install Azure Advanced Threat Protection Silently | Microsoft Docs
description: This describes how to silently install Azure ATP.
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 11/26/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 24eca4c6-c949-42ea-97b9-41ef0fb611f1

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---


# Azure ATP switches and silent installation
This article provides guidance and instructions for Azure ATP switches and silent installation.

## Prerequisites

Azure ATP requires the installation of Microsoft .NET Framework 4.7. 

When you install Azure ATP, .Net Framework 4.7 is automatically installed as part of the deployment of Azure ATP.

> [!IMPORTANT] 
> Make sure that you have the latest version of .Net Framework installed. If a previous version of .Net is installed, your Azure ATP silent installation will get stuck in a loop and fail to install. 

> [!NOTE] 
> The installation of .Net framework 4.7 may require rebooting the server. When installing the Azure ATP sensor on domain controllers, consider scheduling a maintenance window for the domain controllers.
Using Azure ATP silent installation, the installer is configured to automatically restart the server at the end of the installation (if necessary). Make sure to run silent installation only during a maintenance window. Because of a Windows Installer bug, the *norestart* flag cannot be reliably used to make sure the server does not restart.

To track your deployment progress, monitor the Azure ATP installer logs, which are located in **%AppData%\Local\Temp**.


## Azure ATP sensor silent installation

> [!NOTE]
> When silently deploying the Azure ATP sensor via System Center Configuration Manager or other software deployment system, it is recommended to create two deployment packages:</br>- Net Framework 4.7 which may include rebooting the domain controller</br>- Azure ATP sensor. </br>Make the Azure ATP sensor package dependent on the deployment of the .Net Framework package deployment. </br>Get the [.Net Framework 4.7 offline deployment package](https://support.microsoft.com/help/3186497/the-net-framework-4-7-offline-installer-for-windows). 


Use the following command to perform a fully silent install of the Azure ATP sensor:

**cmd.exe syntax**:

    "Azure ATP sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" AccessKey="<Access Key>"

**Powershell syntax**:

    ./"Azure ATP sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" AccessKey="<Access Key>"

> [!NOTE]
> When using the Powershell syntax, omitting the **./** preface results in an error that prevents silent installation.

> [!NOTE]
> Copy the access key from the Azure ATP portal **Configuration** section, **Sensor** page.


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
> |InstallationPath|InstallationPath=""|No|Sets the path for the installation of AATP Sensor binaries. Default path: %programfiles%\Azure Advanced Threat Protection sensor
> |AccessKey|AccessKey="\*\*"|Yes|Sets the access key that is used to register the Azure ATP sensor with the Azure ATP instance.|

**Examples**:
Use the following command to silently install the Azure ATP sensor:

    "Azure ATP sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" AccessKey="mmAOkLYCzfH8L/zUIsH24BIJBevlAWu7wUcSfIkRJufpuEojaDHYdjrNs0P3zpD+/bObKfLS0puD7biT5KDf3g=="

## Proxy authentication

Use the following commands to complete proxy authentication:

**Syntax**:


> [!div class="mx-tableFixed"]
> 
> |Name|Syntax|Mandatory for silent installation?|Description|
> |-------------|----------|---------|---------|
> |ProxyUrl|ProxyUrl="https\://proxy.contoso.com:8080"|No|Specifies the ProxyUrl and port number for the Azure ATP sensor.|
> |ProxyUserName|ProxyUserName="Contoso\ProxyUser"|No|If your proxy service requires authentication, supply a user name in the DOMAIN\user format.|
> |ProxyUserPassword|ProxyUserPassword="P@ssw0rd"|No|Specifies the password for proxy user name. *Credentials are encrypted and stored locally by the Azure ATP sensor.|

## Update the Azure ATP sensor

Use the following command to silently update the Azure ATP sensor:

**Syntax**:

    Azure ATP sensor Setup.exe [/quiet] [/Help] [NetFrameworkCommandLineArguments="/q"]


**Installation options**:

> [!div class="mx-tableFixed"]
> 
> |Name|Syntax|Mandatory for silent installation?|Description|
> |-------------|----------|---------|---------|
> |Quiet|/quiet|Yes|Runs the installer displaying no UI and no prompts.|
> |Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|
> |NetFrameworkCommandLineArguments="/q"|NetFrameworkCommandLineArguments="/q"|Yes|Specifies the parameters for the .Net Framework installation. Must be set to enforce the silent installation of .Net Framework.|


**Examples**:
To update the Azure ATP sensor silently:

    Azure ATP sensor Setup.exe /quiet NetFrameworkCommandLineArguments="/q"

## Uninstall the Azure ATP sensor silently

Use the following command to perform a silent uninstall of the Azure ATP sensor:
**Syntax**:

    Azure ATP sensor Setup.exe [/quiet] [/Uninstall] [/Help]

**Installation options**:

> [!div class="mx-tableFixed"]
> 
> |Name|Syntax|Mandatory for silent uninstallation?|Description|
> |-------------|----------|---------|---------|
> |Quiet|/quiet|Yes|Runs the uninstaller displaying no UI and no prompts.|
> |Uninstall|/uninstall|Yes|Runs the silent uninstallation of the Azure ATP sensor from the server.|
> |Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|

**Examples**:
To silently uninstall the Azure ATP sensor from the server:


    Azure ATP sensor Setup.exe /quiet /uninstall




## See Also

- [Azure ATP prerequisites](atp-prerequisites.md)
- [Install the Azure ATP sensor](install-atp-step4.md)
- [Configure the Azure ATP sensor](install-atp-step5.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
