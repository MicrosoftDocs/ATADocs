---
# required metadata

title: Install Azure Advanced Threat Protection - Step 4 | Microsoft Docs
description: Step four of installing Azure ATP helps you to install the Azure ATP standalone sensor.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/18/2017
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

## Step 4. Install the Azure ATP sensor

Before installing the Azure ATP standalone sensor on a dedicated server, validate that port mirroring is properly configured and that the Azure ATP standalone sensor can see traffic to and from the domain controllers. For more information, see [Validate port mirroring](validate-port-mirroring.md).


> [!IMPORTANT]
>Make sure .Net Framework 4.7 is installed on the machine. If .Net Framework 4.7 is not installed the Azure ATP sensor setup package will install it which will require a reboot of the server. Verify that the machine has connectivity to the Azure ATP cloud service endpoint: https://triprd1wceuw1sensorapi.atp.azure.com (for Europe) or https://triprd1wcuse1sensorapi.atp.azure.com (for the US).

Perform the following steps on the Azure ATP Sensor server or domain controller.

1.  Extract the files from the zip file. 
> [!NOTE] 
> Installing directly from the zip file fails.

2.  Run **Azure ATP sensor setup.exe** and follow the setup wizard.

3.  On the **Welcome** page, select your language and click **Next**.

     ![Azure ATP standalone sensor installation language](media/sensor-install-language.png)


4.  The installation wizard automatically checks if the server is a domain controller or a dedicated server. If it is a domain controller, the Azure ATP Sensor is installed, if it is a dedicated server, the Azure ATP standalone sensor is installed. 
    
    For example, for an Azure ATP standalone sensor, the following screen is displayed to let you know that an Azure ATP standalone sensor will be installed on your dedicated server:
    
    ![Azure ATP standalone sensor installation](media/sensor-install-deployment-type.png)

    Click **Next**.

    > [!NOTE] 
    > If the domain controller or dedicated server does not meet the minimum hardware requirements for the installation, you receive a warning. This does not prevent you from clicking **Next** and proceeding with installation. This might be the right option for installation of Azure ATP in a small lab test environment in which you don't need as much room for data storage. For production environments, it is highly recommended to work with Azure ATP's [capacity planning](atp-capacity-planning.md) guide to make sure your domain controllers or dedicated servers meet the necessary requirements.

4.  Under **Configure the sensor**, enter the installation path and the access key that you copied from the previous step, based on your environment:

    ![Azure ATP standalone sensor configuration image](media/sensor-install-config.png)

      - Installation Path: This is the location where the Azure ATP standalone sensor is installed. By default this is  %programfiles%\Azure Advanced Threat Protection Sensor. Leave the default value.

      - Access key: This is retrieved from the workspace portal in the previous step.
    
5. Click **Install**. The following components are installed and configured during the installation of the Azure ATP sensor:

    -   KB 3047154 (for Windows Server 2012 R2 only)

        > [!IMPORTANT]
        > -   Do not install KB 3047154 on a virtualization host (the host that is running the virtualization, it is fine to run it on a virtual machine). This may cause port mirroring to stop working properly. 
        > -   Do not install Message Analyzer, Wireshark, or other network capture software on the Azure ATP standalone sensor. If you need to capture network traffic, install and use Microsoft Network Monitor 3.4.

    -   Azure ATP standalone sensor service
    -   Microsoft Visual C++ 2013 Redistributable

5.  After the installation completes, click **Launch** to open your browser and log in to the Azure ATP workspace portal.


>[!div class="step-by-step"]
[« Step 3](install-atp-step3.md)
[Step 5 »](install-atp-step5.md)


## See Also

- [Azure ATP sizing tool](http://aka.ms/trisizingtool)

- [Configure event collection](configure-event-collection.md)

- [Azure ATP prerequisites](atp-prerequisites.md)

