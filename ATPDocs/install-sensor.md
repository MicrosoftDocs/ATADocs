---
title: Install the Microsoft Defender for Identity sensor
description: Learn how to download and install the Microsoft Defender for Identity sensors on your domain controllers.
ms.date: 03/28/2022
ms.topic: how-to
---

# Install the Microsoft Defender for Identity sensor

Learn how to download and install the [!INCLUDE [Product long](includes/product-long.md)] sensor on domain controllers.

## Add and download a sensor

1. In [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings** and then **Identities**.

    ![Go to Settings, then Identities.](media/settings-identities.png)

1. Select the **Sensors** page, which displays all of your Defender for Identity sensors.

    [![Sensor page.](media//sensor-page.png)](media/sensor-page.png#lightbox)

1. Select **Add sensor**.

    ![Add sensor.](media/add-sensor.png)

1. A pane will open, providing you with a button to download the sensor installer and a generated access key.

    ![Download installer and access key.](media/installer-access-key.png)

1. Select **Download installer** to save the package locally. The zip file includes the following files:

    - The Defender for Identity sensor installer

    - The configuration setting file with the required information to connect to the Defender for Identity cloud service

1. Copy the **Access key**. The access key is required for the Defender for Identity sensor to connect to your Defender for Identity instance. The access key is a one-time-password for sensor deployment, after which all communication is performed using certificates for authentication and TLS encryption. Use the **Regenerate key** button if you ever need to regenerate the new access key. It won't affect any previously deployed sensors, because it's only used for initial registration of the sensor.

1. Copy the package to the dedicated server or domain controller onto which you're installing the Defender for Identity sensor.

## Install the Defender for Identity sensor

### Prerequisites

- A downloaded copy of your [[!INCLUDE [Product short](includes/product-short.md)] sensor setup package](#add-and-download-a-sensor) and the access key.
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

> [!NOTE]
> Beginning with version 2.176, when installing the sensor from a new package, the sensor's version under **Add/Remove Programs** will appear with the full version number (for example, 2.176.x.y), as opposed to the static 2.0.0.0 that was previously shown. It will continue to show that version (the one installed through the package) even though the version will be updated through the automatic updates from the Defender for Identity cloud services. The real version can be seen in the [sensor settings page](https://security.microsoft.com/settings/identities?tabid=sensor) in the portal, in the executable path or in the file version.

## Post-installation steps for AD FS servers

If you installed the sensor on AD FS servers, follow the steps in [Post-installation steps for AD FS servers](active-directory-federation-services.md#post-installation-steps-for-ad-fs-servers).

## Next steps

- Learn how to correctly [configure Microsoft Defender for Identity sensor settings](configure-sensor-settings.md) to start seeing data.
