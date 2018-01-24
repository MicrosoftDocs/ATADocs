---
# required metadata

title: Install Azure Threat Protection Silently | Microsoft Docs
description: This describes how to silently install ATP.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
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

*Applies to: Azure Threat Protection*


# ATP Silent Installation
This article provides instructions for silently installing ATP.

## Prerequisites

ATP  requires the installation of Microsoft .NET Framework 4.6.1. 

When you install or update ATP, .Net Framework 4.6.1 is automatically installed as part of the deployment of Microsoft ATP.

> [!Note] 
> The installation of .Net framework 4.6.1 may require rebooting the server. When installing ATP Standalone Sensor on Domain Controllers, consider scheduling a maintenance window for these Domain Controllers.
When using ATP silent installation method, the installer is configured to automatically restart the server at the end of the installation (if necessary). Because of a Windows Installer bug, the norestart flag cannot be reliably used to make sure the server does not restart, so make sure to only run silent installation during a maintenance window.

To track the progress of the deployment, monitor ATP installer logs, which are located in **%AppData%\Local\Temp**.


## Install the Azure ATP cloud service

Use the following command to install the Azure ATP cloud service:

**Syntax**:

    "Microsoft Azure ATP cloud service Setup.exe" [/quiet] [/Help] [--LicenseAccepted] [NetFrameworkCommandLineArguments="/q"] [InstallationPath="<InstallPath>"] [DatabaseDataPath= "<DBPath>"] [CenterIpAddress=<CenterIPAddress>] [CenterPort=<CenterPort>] [CenterCertificateThumbprint="<CertThumbprint>"] 
    [ConsoleIpAddress=<ConsoleIPAddress>] [ConsoleCertificateThumbprint="<CertThumbprint >"]
    
**Installation options**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent installation?|Description|
|-------------|----------|---------|---------|
|Quiet|/quiet|Yes|Runs the installer displaying no UI and no prompts.|
|Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|
|NetFrameworkCommandLineArguments="/q"|NetFrameworkCommandLineArguments="/q"|Yes|Specifies the parameters for the .Net Framework installation. Must be set to enforce the silent installation of .Net Framework.|
|LicenseAccepted|--LicenseAccepted|Yes|Indicates that the license was read and approved. Must be set on silent installation.|

**Installation parameters**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent installation?|Description|
|-------------|----------|---------|---------|
|InstallationPath|InstallationPath="<InstallPath>"|No|Sets the path for the installation of ATP binaries. Default path: C:\Program Files\Microsoft Azure Threat Protection\Center|
|DatabaseDataPath|DatabaseDataPath= "<DBPath>"|No|Sets the path for the ATP Database data folder. Default path: C:\Program Files\Microsoft Azure Threat Protection\Center\MongoDB\bin\data|
|CenterIpAddress|CenterIpAddress=<CenterIPAddress>|Yes|Sets the IP address of the Azure ATP cloud service Service|
|CenterPort|CenterPort=<CenterPort>|Yes|Sets the network port of the Azure ATP cloud service Service|
|CenterCertificateThumbprint|CenterCertificateThumbprint="<CertThumbprint>"|No|Sets the certificate thumbprint for the Azure ATP cloud service Service. This Certificate is used to secure communication between the Azure ATP cloud service and the ATP Standalone Sensor. If not set, the installation generates a self-signed certificate.|
|ConsoleIpAddress|ConsoleIpAddress=<ConsoleIPAddress>|Yes|Sets the IP address of the ATP Console|
|ConsoleCertificateThumbprint|ConsoleCertificateThumbprint="<CertThumbprint >"|No|Specifies the certificate thumbprint for the ATP Console. This Certificate is used to validate the identity of the ATP Console website. If not specified, the installation generates a self-signed certificate|

**Examples**:
To install the Azure ATP cloud service with default installation paths and a single IP address:

    "Microsoft Azure ATP cloud service Setup.exe" /quiet --LicenseAccepted NetFrameworkCommandLineArguments="/q" CenterIpAddress=192.168.0.10
    CenterPort=444 ConsoleIpAddress=192.168.0.10

To install the Azure ATP cloud service with default installation paths, two IP addresses, and user-defined certificate thumbprints:

    "Microsoft Azure ATP cloud service Setup.exe" /quiet --LicenseAccepted NetFrameworkCommandLineArguments ="/q" CenterIpAddress=192.168.0.10 CenterPort=443 CenterCertificateThumbprint= ‎"1E2079739F624148ABDF502BF9C799FCB8C7212F"
    ConsoleIpAddress=192.168.0.11  ConsoleCertificateThumbprint="G9530253C976BFA9342FD1A716C0EC94207BFD5A"

## Update the Azure ATP cloud service

Use the following command to update the Azure ATP cloud service:

**Syntax**:

    "Microsoft Azure ATP cloud service Setup.exe" [/quiet] [/Help] [NetFrameworkCommandLineArguments="/q"]


**Installation options**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent installation?|Description|
|-------------|----------|---------|---------|
|Quiet|/quiet|Yes|Runs the installer displaying no UI and no prompts.|
|Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|
|NetFrameworkCommandLineArguments="/q"|NetFrameworkCommandLineArguments="/q"|Yes|Specifies the parameters for the .Net Framework installation. Must be set to enforce the silent installation of .Net Framework.|


When updating ATP, the installer automatically detects that ATP is already installed on the server, and no update installation option is required.

**Examples**:
To update the Azure ATP cloud service silently. In large environments, the Azure ATP cloud service update can take a while to complete. Monitor ATP logs to track the progress of the update.

    	"Microsoft Azure ATP cloud service Setup.exe" /quiet NetFrameworkCommandLineArguments="/q"

## Uninstall the Azure ATP cloud service silently

Use the following command to perform a silent uninstall of the Azure ATP cloud service:
**Syntax**:

    Microsoft Azure ATP cloud service Setup.exe [/quiet] [/Uninstall] [/Help]
     [--DeleteExistingDatabaseData]

**Installation options**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent uninstallation?|Description|
|-------------|----------|---------|---------|
|Quiet|/quiet|Yes|Runs the uninstaller displaying no UI and no prompts.|
|Uninstall|/uninstall|Yes|Runs the silent uninstallation of the Azure ATP cloud service from the server.|
|Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|

**Installation parameters**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent uninstallation?|Description|
|-------------|----------|---------|---------|
|DeleteExistingDatabaseData|DeleteExistingDatabaseData|No|Deletes all the files in the existing database.|

**Examples**:
To silently uninstall the Azure ATP cloud service from the server, removing all existing database data:


    "Microsoft Azure ATP cloud service Setup.exe" /quiet /uninstall --DeleteExistingDatabaseData

## ATP Standalone Sensor Silent Installation

> [!NOTE]
> When silently deploying the ATP Sensor via System Center Configuration Manager or other software deployment system, it is recommended to create two deployment packages:</br>- Net Framework 4.6.1 including rebooting the domain controller</br>- ATP Standalone Sensor. </br>Make the ATP Standalone Sensor package dependent on the deployment of the .Net Framework package deployment. </br>Get the [.Net Framework 4.6.1 offline deployment package](https://www.microsoft.com/download/details.aspx?id=49982). 


Use the following command to silently install the ATP Standalone Sensor:

**Syntax**:

    Microsoft ATP Standalone Sensor Setup.exe [/quiet] [/Help] [NetFrameworkCommandLineArguments ="/q"] 
    [ConsoleAccountName="<AccountName>"] 
    [ConsoleAccountPassword="<AccountPassword>"]

> [!NOTE]
> If you are working on a domain joined computer and have logged in using your ATP admin username and password, it is unnecessary to provide your credentials here.


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
|ConsoleAccountName|ConsoleAccountName="<AccountName>"|Yes|Sets the name of the user account (user@domain.com) that is used to register the ATP Standalone Sensor with the Azure ATP cloud service.|
|ConsoleAccountPassword|ConsoleAccountPassword="<AccountPassword>"|Yes|Sets the password for the user account (user@domain.com) that is used to register the ATP Standalone Sensor with the Azure ATP cloud service.|

**Examples**:
To silently install the ATP Standalone Sensor, log into the domain joined computer with your ATP admin credentials so that you do not need to specify credentials as part of the installation. Otherwise, register it with the Azure ATP cloud service using the specified credentials:

    "Microsoft ATP Standalone Sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" 
    ConsoleAccountName="user@contoso.com" ConsoleAccountPassword="userpwd"
    

## Update the ATP Standalone Sensor

Use the following command to silently update the ATP Standalone Sensor:

**Syntax**:

    Microsoft ATP Standalone Sensor Setup.exe [/quiet] [/Help] [NetFrameworkCommandLineArguments="/q"]


**Installation options**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent installation?|Description|
|-------------|----------|---------|---------|
|Quiet|/quiet|Yes|Runs the installer displaying no UI and no prompts.|
|Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|
|NetFrameworkCommandLineArguments="/q"|NetFrameworkCommandLineArguments="/q"|Yes|Specifies the parameters for the .Net Framework installation. Must be set to enforce the silent installation of .Net Framework.|


**Examples**:
To update the ATP Standalone Sensor silently:

    	Microsoft ATP Standalone Sensor Setup.exe /quiet NetFrameworkCommandLineArguments="/q"

## Uninstall the ATP Standalone Sensor silently

Use the following command to perform a silent uninstall of the ATP Standalone Sensor:
**Syntax**:

    Microsoft ATP Standalone Sensor Setup.exe [/quiet] [/Uninstall] [/Help]
    
**Installation options**:

> [!div class="mx-tableFixed"]
|Name|Syntax|Mandatory for silent uninstallation?|Description|
|-------------|----------|---------|---------|
|Quiet|/quiet|Yes|Runs the uninstaller displaying no UI and no prompts.|
|Uninstall|/uninstall|Yes|Runs the silent uninstallation of the ATP Standalone Sensor from the server.|
|Help|/help|No|Provides help and quick reference. Displays the correct use of the setup command including a list of all options and behaviors.|

**Examples**:
To silently uninstall the ATP Standalone Sensor from the server:


    Microsoft ATP Standalone Sensor Setup.exe /quiet /uninstall
    









## See Also

- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATP prerequisites](ata-prerequisites.md)