---
# required metadata

title: Install Azure Advanced Threat Protection - Step 4 | Microsoft Docs
description: Step four of installing Azure ATP helps you to install the Azure ATP Standalone Sensor.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/14/2017
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 51911e39-76c7-4dcd-bc0b-ec6235d0403f

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



# Install Azure ATP - Step 4

>[!div class="step-by-step"]
[« Step 3](install-atp-step3.md)
[Step 5 »](install-atp-step5.md)

## Step 4. Install the Azure ATP Sensor

Before installing the Azure ATP Standalone Sensor on a dedicated server, validate that port mirroring is properly configured and that the Azure ATP Standalone Sensor can see traffic to and from the domain controllers. For more information, see [Validate port mirroring](validate-port-mirroring.md).


> [!IMPORTANT]
>Make sure .NET 4.7 is installed on the machine. Verify that the machine has connectivity to the Azure ATP cloud service endpoint: https://triprd1wceuw1sensorapi.atp.azure.com (for Europe) or https://triprd1wcuse1sensorapi.atp.azure.com (for the US).

Perform the following steps on the Azure ATP Sensor server or domain controller.

1.  Extract the files from the zip file. 
> [!NOTE] 
> Installing directly from the zip file fails.

2.  Run **Azure ATP Sensor Setup.exe** and follow the setup wizard.

3.  On the **Welcome** page, select your language and click **Next**.

     ![Azure ATP Standalone Sensor installation language](media/sensor-install-language.png)


4.  The installation wizard automatically checks if the server is a domain controller or a dedicated server. If it is a domain controller, the Azure ATP Sensor is installed, if it is a dedicated server, the Azure ATP Standalone Sensor is installed. 
    
    For example, for an Azure ATP Standalone Sensor, the following screen is displayed to let you know that an Azure ATP Standalone Sensor will be installed on your dedicated server:
    
    ![Azure ATP Standalone Sensor installation](media/sensor-install-deployment-type.png)

    Click **Next**.

    > [!NOTE] 
    > If the domain controller or dedicated server does not meet the minimum hardware requirements for the installation, you receive a warning. This does not prevent you from clicking **Next** and proceeding with installation. This might be the right option for installation of Azure ATP in a small lab test environment in which you don't need as much room for data storage. For production environments, it is highly recommended to work with Azure ATP's [capacity planning](atp-capacity-planning.md) guide to make sure your domain controllers or dedicated servers meet the necessary requirements.

4.  Under **Configure the Sensor**, enter the installation path and the access key, based on your environment:

    ![Azure ATP Standalone Sensor configuration image](media/sensor-install-config.png)

    > [!NOTE]
    > When you deploy the Azure ATP Standalone Sensor, you do not have to provide credentials. If the Azure ATP Standalone Sensor installation fails to retrieve your credentials using single sign-on (for example, this may happen if the Azure ATP cloud service is not in the domain, if the Azure ATP Standalone Sensor isn't in the domain, you do not have Azure ATP admin credentials), you are prompted to provide credentials, as in the following screen: 

   - Installation Path: This is the location where the Azure ATP Standalone Sensor is installed. By default this is  %programfiles%\Azure Advanced Threat Protection\Sensor. Leave the default value.

   - Access key: 
    
5. Click **Install**. The following components are installed and configured during the installation of the Azure ATP Standalone Sensor:

    -   KB 3047154 (for Windows Server 2012 R2 only)

        > [!IMPORTANT]
        > -   Do not install KB 3047154 on a virtualization host (the host that is running the virtualization, it is fine to run it on a virtual machine). This may cause port mirroring to stop working properly. 
        > -   Do not install Message Analyzer, Wireshark, or other network capture software on the Azure ATP Standalone Sensor. If you need to capture network traffic, install and use Microsoft Network Monitor 3.4.

    -   Azure ATP Standalone Sensor service
    -   Microsoft Visual C++ 2013 Redistributable

5.  After the installation completes, for the Azure ATP Sensor, click **Launch** to open your browser and log in to the Azure ATP workspace portal, for the Azure ATP Sensor, click **Finish**.


>[!div class="step-by-step"]
[« Step 3](install-atp-step3.md)
[Step 5 »](install-atp-step5.md)


## See Also

- [Azure ATP sizing tool](http://aka.ms/trisizingtool)

- [Configure event collection](configure-event-collection.md)

- [Azure ATP prerequisites](atp-prerequisites.md)

