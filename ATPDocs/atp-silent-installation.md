---
# required metadata

title: Install Azure Advanced Threat Protection Silently | Microsoft Docs
description: This describes how to silently install Azure ATP.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/14/2017
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 24eca4c6-c949-42ea-97b9-41ef0fb611f1

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*


# Azure ATP silent installation
This article provides instructions for silently installing Azure ATP.

## Prerequisites

Azure ATP  requires the installation of Microsoft .NET Framework 4.7. 

When you install Azure ATP, .Net Framework 4.7 is automatically installed as part of the deployment of Azure ATP.

> [!Note] 
> The installation of .Net framework 4.7 may require rebooting the server. When installing Azure ATP Sensor on Domain Controllers, consider scheduling a maintenance window for these Domain Controllers.
When using Azure ATP silent installation method, the installer is configured to automatically restart the server at the end of the installation (if necessary). Because of a Windows Installer bug, the norestart flag cannot be reliably used to make sure the server does not restart, so make sure to only run silent installation during a maintenance window.

To track the progress of the deployment, monitor Azure ATP installer logs, which are located in **%AppData%\Local\Temp**.



## Azure ATP Sensor silent installation

> [!NOTE]
> When silently deploying the Azure ATP Sensor via System Center Configuration Manager or other software deployment system, it is recommended to create two deployment packages:</br>- Net Framework 4.7 including rebooting the domain controller</br>- Azure ATP Sensor. </br>Make the Azure ATP Sensor package dependent on the deployment of the .Net Framework package deployment. </br>Get the [.Net Framework 4.7 offline deployment package](https://www.microsoft.com/download/details.aspx?id=49982). 


Use the following command to silently install the Azure ATP Sensor:

**Syntax**:

    Azure ATP Sensor Setup.exe [/quiet] [/Help] [NetFrameworkCommandLineArguments ="/q"] 
    [ConsoleAccountName="<AccountName>"] 
    [ConsoleAccountPassword="<AccountPassword>"]

> [!NOTE]
> Copy the access key from the workspace portal under **Configuration** and then **Sensors**.


**Installation options**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent installation?|Description|
|-------------|----------|---------|---------|
|Quiet|/quiet|Yes|Runs the installer displaying no UI and no prompts.|
|Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|
|NetFrameworkCommandLineArguments="/q"|NetFrameworkCommandLineArguments="/q"|Yes|Specifies the parameters for the .Net Framework installation. Must be set to enforce the silent installation of .Net Framework.|

**Installation parameters**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent installation?|Description|
|-------------|----------|---------|---------|
|AccessKey|AccessKey="**"|Yes|Sets the access key that is used to register the Azure ATP Sensor with the Azure ATP workspace.|

**Examples**:
To silently install the Azure ATP Sensor, log into the domain joined computer with your Azure ATP admin credentials so that you do not need to specify credentials as part of the installation. Otherwise, register it with the Azure ATP cloud service using the specified credentials:

    "Azure ATP Sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" 
    AccessKey="3WlO0uKW7lY6Lk0+dfkfkJQ0qZV6aSq5WxLf71+fuBhggCl/BMs9JxfAwi7oy9vYGviazUS1EPpzte7z8s4grw==" 
    

## Update the Azure ATP Sensor

Use the following command to silently update the Azure ATP Sensor:

**Syntax**:

    Azure ATP  Sensor Setup.exe [/quiet] [/Help] [NetFrameworkCommandLineArguments="/q"]


**Installation options**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent installation?|Description|
|-------------|----------|---------|---------|
|Quiet|/quiet|Yes|Runs the installer displaying no UI and no prompts.|
|Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|
|NetFrameworkCommandLineArguments="/q"|NetFrameworkCommandLineArguments="/q"|Yes|Specifies the parameters for the .Net Framework installation. Must be set to enforce the silent installation of .Net Framework.|


**Examples**:
To update the Azure ATP Sensor silently:

    	Azure ATP Sensor Setup.exe /quiet NetFrameworkCommandLineArguments="/q"

## Uninstall the Azure ATP Sensor silently

Use the following command to perform a silent uninstall of the Azure ATP Sensor:
**Syntax**:

    Azure ATP Sensor Setup.exe [/quiet] [/Uninstall] [/Help]
    
**Installation options**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent uninstallation?|Description|
|-------------|----------|---------|---------|
|Quiet|/quiet|Yes|Runs the uninstaller displaying no UI and no prompts.|
|Uninstall|/uninstall|Yes|Runs the silent uninstallation of the Azure ATP Sensor from the server.|
|Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|

**Examples**:
To silently uninstall the Azure ATP Sensor from the server:


    Azure ATP Sensor Setup.exe /quiet /uninstall
    



## See Also

- [Check out the Azure ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [Azure ATP prerequisites](ata-prerequisites.md)