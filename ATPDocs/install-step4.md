---
title: Install Microsoft Defender for Identity sensor quickstart
description: Step four of installing Microsoft Defender for Identity helps you to install the Defender for Identity sensor.
ms.date: 02/17/2021
ms.topic: quickstart
---

# Quickstart: Install the Microsoft Defender for Identity sensor

In this quickstart, you'll install the [!INCLUDE [Product long](includes/product-long.md)] sensor on a domain controller. If you prefer a silent installation, see the [Silent installation](silent-installation.md) article.

## Prerequisites

- An [[!INCLUDE [Product short](includes/product-short.md)] instance](install-step1.md) that's [connected to Active Directory](install-step2.md).
- A downloaded copy of your [[!INCLUDE [Product short](includes/product-short.md)] sensor setup package](install-step3.md) and the access key.
- Make sure Microsoft .NET Framework 4.7 or later is installed on the machine. If Microsoft .NET Framework 4.7 or later isn't installed, the [!INCLUDE [Product short](includes/product-short.md)] sensor setup package installs it, which may require a reboot of the server.
- For sensor installations on Active Directory Federation Services (AD FS) servers, see [AD FS Prerequisites](active-directory-federation-services.md#prerequisites).
- Install the [Npcap driver](/defender-for-identity/technical-faq#winpcap-and-npcap-drivers). For download and installation instructions, see [How do I download and install the Npcap driver](/defender-for-identity/technical-faq#how-do-i-download-and-install-the-npcap-driver).

>[!NOTE]
>When installing the sensor on Windows Server Core, follow the steps for [silent installation](silent-installation.md).

## Install the sensor

Perform the following steps on the domain controller or AD FS server.

1. Verify the machine has connectivity to the relevant [[!INCLUDE [Product short](includes/product-short.md)] cloud service](configure-proxy.md#enable-access-to-defender-for-identity-service-urls-in-the-proxy-server) endpoint(s).
1. Extract the installation files from the zip file. Installing directly from the zip file will fail.
1. Run **Azure ATP sensor setup.exe** with elevated privileges (**Run as administrator**) and follow the setup wizard.
1. On the **Welcome** page, select your language and select **Next**.

    ![[!INCLUDE [Product short.](includes/product-short.md)] standalone sensor installation language](media/sensor-install-language.png)

1. The installation wizard automatically checks if the server is a domain controller/ AD FS server or a dedicated server. If it's a domain controller / AD FS server, the [!INCLUDE [Product short](includes/product-short.md)] sensor is installed. If it's a dedicated server, the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor is installed.

    For example, for a [!INCLUDE [Product short](includes/product-short.md)] sensor, the following screen is displayed to let you know that a [!INCLUDE [Product short](includes/product-short.md)] sensor is installed on your dedicated server:

    ![[!INCLUDE [Product short.](includes/product-short.md)] sensor installation](media/sensor-install-deployment-type.png)

    Select **Next**.

    > [!NOTE]
    > A warning is issued if the domain controller / AD FS server or dedicated server does not meet the minimum hardware requirements for the installation. The warning doesn't prevent you from clicking **Next**, and proceeding with the installation. It can still be the right option for the installation of [!INCLUDE [Product short](includes/product-short.md)] in a small lab test environment where less room for data storage is required. For production environments, it is highly recommended to work with [!INCLUDE [Product short](includes/product-short.md)]'s [capacity planning](capacity-planning.md) guide to make sure your domain controllers or dedicated servers meet the necessary requirements.

1. Under **Configure the sensor**, enter the installation path and the access key that you copied from the previous step, based on your environment:

    ![[!INCLUDE [Product short.](includes/product-short.md)] sensor configuration image](media/sensor-install-config.png)

    - Installation path: The location where the [!INCLUDE [Product short](includes/product-short.md)] sensor is installed. By default the path is  `%programfiles%\Azure Advanced Threat Protection sensor`. Leave the default value.
    - Access key: Retrieved from the [!INCLUDE [Product short](includes/product-short.md)] portal in the previous step.

1. Select **Install**. The following components are installed and configured during the installation of the [!INCLUDE [Product short](includes/product-short.md)] sensor:

    - KB 3047154 (for Windows Server 2012 R2 only)

        > [!IMPORTANT]
        >
        > - Don't install KB 3047154 on a virtualization host (the host that is running the virtualization -  it's fine to run it on a virtual machine). This may cause port mirroring to stop working properly.
        > - If Wireshark is installed on the [!INCLUDE [Product short](includes/product-short.md)] sensor machine, after you run Wireshark you need to restart the [!INCLUDE [Product short](includes/product-short.md)] sensor, because it uses the same drivers.

    - [!INCLUDE [Product short](includes/product-short.md)] sensor service and [!INCLUDE [Product short](includes/product-short.md)] sensor updater service
    - Microsoft Visual C++ 2013 Redistributable

## Post-installation steps for AD FS servers

If you installed the sensor on AD FS servers, follow the steps in [Post-installation steps for AD FS servers](active-directory-federation-services.md#post-installation-steps-for-ad-fs-servers).

## Next steps

- Learn how to correctly [configure Microsoft Defender for Identity sensor settings](install-step5.md) to start seeing data.

## Join the Community

Have more questions, or an interest in discussing [!INCLUDE [Product short](includes/product-short.md)] and related security with others? Join the [[!INCLUDE [Product short](includes/product-short.md)] Community](<https://aka.ms/MDIcommunity>) today!
