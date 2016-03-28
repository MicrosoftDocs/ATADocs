---
title: Install ATA - Step 4 | Microsoft Advanced Threat Analytics
ms.custom:
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology:
  - security
ms.tgt_pltfrm: na
ms.topic: get-started-article
ms.assetid: 3715b69e-e631-449b-9aed-144d0f9bcee7
author: Rkarlin
---
# Install ATA - Step 4

>[!div class="step-by-step"]
[« Step 3](install-ata-step3.md)
[Step 5 »](install-ata-step5.md)

## <a name="InstallATAGW"></a>Step 4. Install the ATA Gateway
Before installing the ATA Gateway, validate that port mirroring is properly configured and that the ATA Gateway can see traffic to and from the domain controllers. See [Validate port mirroring](/advanced-threat-analytics/plandesign/validate-port-mirroring) for more information.

> [!IMPORTANT]
> Make sure that [KB2919355](http://support.microsoft.com/kb/2919355/) has been installed.  Run the following PowerShell cmdlet to check if the hotfix is installed:
>
> `Get-HotFix -Id kb2919355`

Perform the following steps on the ATA Gateway server.

1.  Extract the files from the zip file.

2.  From an elevated command prompt, run Microsoft ATA Gateway Setup.exe and follow the setup wizard.

3.  On the **Welcome** page, select your language and click **Next**.

4.  Under  **ATA Gateway Configuration**, enter the following information based on your environment:

    ![ATA gateway configuration image](media/ATA-Gateway-Configuration.JPG)

    |Field|Description|Comments|
    |---------|---------------|------------|
    |Installation Path|This is the location where the ATA Gateway will be installed. By default this is  %programfiles%\Microsoft Advanced Threat Analytics\Gateway|Leave the default value|
    |ATA Gateway Service SSL certificate|This is the certificate that will be used by the ATA Gateway.|Use a self-signed certificate for lab environments only.|
    |ATA Gateway Registration|Enter the Username and Password of the ATA administrator.|For the ATA Gateway to register with the ATA Center, enter the user name and password of the user who installed the ATA Center. This user must be a member of one of the following local groups on the ATA Center.<br /><br />-   Administrators<br />-   Microsoft Advanced Threat Analytics Administrators **Note:** These credentials are used only for registration and are not stored in ATA.|
    The following components are installed and configured during the installation of the ATA Gateway:

    -   KB 3047154

        > [!IMPORTANT]
        > -   Do not install KB 3047154 on a virtualization host. This may cause port mirroring to stop working properly.
        > -   Do not install Message Analyzer, Wireshark, or other network capture software on the ATA Gateway. If you need to capture network traffic, install and use Microsoft Network Monitor 3.4.

    -   ATA Gateway service

    -   Microsoft Visual C++ 2013 Redistributable

    -   Custom Performance Monitor data collection set

5.  After the installation completes, click **Launch**  to open your browser and log in to the ATA Console.


>[!div class="step-by-step"]
[« Step 3](install-ata-step3.md)
[Step 5 »](install-ata-step5.md)

## See Also

- [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
- [Configure event collection](/advanced-threat-analytics/plandesign/configure-event-collection)
- [ATA prerequisites](/advanced-threat-analytics/plandesign/ata-prerequisites)
