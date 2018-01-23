---
# required metadata

title: Install Azure Threat Protection - Step 4 | Microsoft Docs
description: Step four of installing ATP helps you to install the ATP Gateway.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 6bbc50c3-bfa8-41db-a2f9-56eed68ef5d2

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Threat Protection *



# Install ATP - Step 4

>[!div class="step-by-step"]
[« Step 3](install-ata-step3.md)
[Step 5 »](install-ata-step5.md)

## Step 4. Install the ATP Gateway

Before installing the ATP Gateway on a dedicated server, validate that port mirroring is properly configured and that the ATP Gateway can see traffic to and from the domain controllers. For more information, see [Validate port mirroring](validate-port-mirroring.md).


> [!IMPORTANT]
> Make sure that [KB2919355](http://support.microsoft.com/kb/2919355/) has been installed.  Run the following PowerShell cmdlet to check if the hotfix is installed:
>
> `Get-HotFix -Id kb2919355`

Perform the following steps on the ATP Gateway server.

1.  Extract the files from the zip file. 
> [!NOTE] 
> Installing directly from the zip file fails.

2.  Run **Microsoft ATP Gateway Setup.exe** and follow the setup wizard.

3.  On the **Welcome** page, select your language and click **Next**.

4.  The installation wizard automatically checks if the server is a domain controller or a dedicated server. If it is a domain controller, the ATP Lightweight Gateway is installed, if it is a dedicated server, the ATP Gateway is installed. 
    
    For example, for an ATP Gateway, the following screen is displayed to let you know that an ATP Gateway will be installed on your dedicated server:
    
    ![ATP Gateway installation](media/ata-gw-install.png)
    Click **Next**.

    > [!NOTE] 
    > If the domain controller or dedicated server does not meet the minimum hardware requirements for the installation, you receive a warning. This does not prevent you from clicking **Next** and proceeding with installation. This might be the right option for installation of ATP in a small lab test environment in which you don't need as much room for data storage. For production environments, it is highly recommended to work with ATP's [capacity planning](ata-capacity-planning.md) guide to make sure your domain controllers or dedicated servers meet the necessary requirements.

4.  Under **Configure the Gateway**, enter the following information based on your environment:

    ![ATP gateway configuration image](media/ata-gw-configure.png)

    > [!NOTE]
    > When you deploy the ATP Gateway, you do not have to provide credentials. If the ATP Gateway installation fails to retrieve your credentials using single sign-on (for example, this may happen if the ATP Center is not in the domain, if the ATP Gateway isn't in the domain, you do not have ATP admin credentials), you are prompted to provide credentials, as in the following screen: 

  ![Provide ATP gateway credentials](media/ata-install-credentials.png)

   - Installation Path: This is the location where the ATP Gateway is installed. By default this is  %programfiles%\Microsoft Azure Threat Protection\Gateway. Leave the default value.
    
5. Click **Install**. The following components are installed and configured during the installation of the ATP Gateway:

    -   KB 3047154 (for Windows Server 2012 R2 only)

        > [!IMPORTANT]
        > -   Do not install KB 3047154 on a virtualization host (the host that is running the virtualization, it is fine to run it on a virtual machine). This may cause port mirroring to stop working properly. 
        > -   Do not install Message Analyzer, Wireshark, or other network capture software on the ATP Gateway. If you need to capture network traffic, install and use Microsoft Network Monitor 3.4.

    -   ATP Gateway service
    -   Microsoft Visual C++ 2013 Redistributable
    -   Custom Performance Monitor data collection set

5.  After the installation completes, for the ATP Gateway, click **Launch** to open your browser and log in to the ATP Console, for the ATP Lightweight Gateway, click **Finish**.


>[!div class="step-by-step"]
[« Step 3](install-ata-step3.md)
[Step 5 »](install-ata-step5.md)


## Related Videos
- [ATP Deployment Overview](https://channel9.msdn.com/Shows/Microsoft-Security/Overview-of-ATP-Deployment-in-10-Minutes)
- [Choosing the right ATP Gateway type](https://channel9.msdn.com/Shows/Microsoft-Security/ATP-Deployment-Choose-the-Right-Gateway-Type)

## See Also
- [ATP POC deployment guide](http://aka.ms/atapoc)
- [ATP sizing tool](http://aka.ms/atasizingtool)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATP prerequisites](ata-prerequisites.md)

