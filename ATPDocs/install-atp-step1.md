---
# required metadata

title: Install Azure Threat Protection - Step 1 | Microsoft Docs
description: First step to install ATP involves downloading and installing the Azure ATP cloud service onto your chosen server.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 15ee7d0b-9a0c-46b9-bc71-98d0b4619ed0

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


# Install ATP - Step 1

>[!div class="step-by-step"]
[Step 2 »](install-ata-step2.md)

This installation procedure provides instructions for performing a fresh installation of ATP 1.8. For information on updating an existing ATP deployment from an earlier version, see [the ATP migration guide for ](ata-update-1.8-migration-guide.md).

> [!IMPORTANT] 
> If using Windows 2012 R2, you can install KB2934520 on the Azure ATP cloud service server and on the ATP Standalone Sensor servers before beginning installation, otherwise the ATP installation installs this update and requires a restart in the middle of the ATP installation.

## Step 1. Download and Install the Azure ATP cloud service
After you have verified that the server meets the requirements, you can proceed with the installation of the Azure ATP cloud service.
    
> [!NOTE]
>If you acquired a license for Enterprise Mobility + Security (EMS) directly via the Office 365 portal or through the Cloud Solution Partner (CSP) licensing model and you do not have access to ATP through the Microsoft Volume Licensing Center (VLSC), contact Microsoft Customer Support to obtain the process to activate Azure Threat Protection (ATP).

Perform the following steps on the Azure ATP cloud service server.

1.  Download ATP from the [Microsoft Volume Licensing Service Center](https://www.microsoft.com/Licensing/servicecenter/default.aspx) or from the [TechNet Evaluation Center](http://www.microsoft.com/evalcenter/) or from [MSDN](https://msdn.microsoft.com/subscriptions/downloads).

2.  Log in to the computer on to which you are installing the Azure ATP cloud service as a user who is a member of the local administrators group.

3.  Run **Microsoft Azure ATP cloud service Setup.EXE** and follow the setup wizard.

> [!NOTE]   
> Make sure to run the installation file from a local drive and not from a mounted ISO file to avoid issues in case a reboot is required as part of the installation.   

4.  If Microsoft .Net Framework is not installed, you are prompted to install it when you start installation. You may be prompted to reboot after .NET Framework installation.
5.  On the **Welcome** page, select the language to be used for the ATP installation screens and click **Next**.

6.  Read the Microsoft Software License Terms and if you accept the terms, click the check box, and then click **Next**.

7.  It is recommended that you set ATP to update automatically. If Windows isn't set to do this on your computer, you get the **Use Microsoft Update to help keep your computer secure and up to date** screen. 
    ![Keep ATP up to date image](media/ata_ms_update.png)

8. Select **Use Microsoft Update when I check for updates (recommended)**. This adjusts the Windows settings to enable updates for other Microsoft products (including ATP), as seen here. 

    ![Windows auto-update image](media/ata_installupdatesautomatically.png)

8.  On the **Configure the Center** page, enter the following information based on your environment:

    |Field|Description|Comments|
    |---------|---------------|------------|
    |Installation Path|This is the location where the Azure ATP cloud service is installed. By default this is  %programfiles%\Microsoft Azure Threat Protection\Center|Leave the default value|
    |Database Data Path|This is the location where the MongoDB database files are located. By default this is %programfiles%\Microsoft Azure Threat Protection\Center\MongoDB\bin\data|Change the location to a place where you have room to grow based on your sizing. **Note:** <ul><li>In production environments, you should use a drive that has enough space based on capacity planning.</li><li>For large deployments the database should be on a separate physical disk.</li></ul>See [ATP capacity planning](ata-capacity-planning.md) for sizing information.|
    |Center Service SSL Certificate|This is the certificate that is used by the ATP Console and Azure ATP cloud service.|Click the key icon to select a certificate installed or check self-signed certificate when deploying in a lab environment. You have the option to create a self-signed certificate.|
        
    ![ATP center configuration image](media/ATP-Center-Configuration.png)

10.  Click **Install** to install the Azure ATP cloud service and its components.
    The following components are installed and configured during the installation of Azure ATP cloud service:

    -   Azure ATP cloud service

    -   MongoDB

    -   Custom Performance Monitor data collection set

    -   Self-signed certificates (if selected during the installation)

11.  When the installation completes, click **Launch**  to open the ATP Console and complete setup on the **Configuration** page.
At this point, you will be brought automatically to the **General** settings page to continue the configuration and the deployment of the ATP Standalone Sensors.
Because you are logging into the site using an IP address, you receive a warning related to the certificate, this is normal and you should click **Continue to this website**.

### Validate installation

1.  Check to see that the service named **Microsoft Azure Threat Protection Center** is running.
2.  On the desktop, click the **Microsoft Azure Threat Protection** shortcut to connect to the ATP Console. Log in with the same user credentials that you used to install the Azure ATP cloud service.



>[!div class="step-by-step"]
[« Pre-install](configure-port-mirroring.md)
[Step 2 »](install-ata-step2.md)

## Related Videos
- [Choosing the right ATP Standalone Sensor type](https://channel9.msdn.com/Shows/Microsoft-Security/ATP-Deployment-Choose-the-Right-Gateway-Type)
- [ATP Deployment Overview](https://channel9.msdn.com/Shows/Microsoft-Security/Overview-of-ATP-Deployment-in-10-Minutes)


## See Also
- [ATP POC deployment guide](http://aka.ms/atapoc)
- [ATP sizing tool](http://aka.ms/atasizingtool)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATP prerequisites](ata-prerequisites.md)

