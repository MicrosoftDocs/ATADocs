---
title: Download the sensor
description: Learn how to download the Microsoft Defender for Identity sensors for your domain controllers.
ms.date: 01/29/2023
ms.topic: how-to
---

# Download the Microsoft Defender for Identity sensor

Learn how to download the Microsoft Defender for Identity sensor for your domain controllers.

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

1. Copy the **Access key**. The access key is required for the Defender for Identity sensor to connect to your Defender for Identity workspace. The access key is a one-time-password for sensor deployment, after which all communication is performed using certificates for authentication and TLS encryption. Use the **Regenerate key** button if you ever need to regenerate the new access key. It won't affect any previously deployed sensors, because it's only used for initial registration of the sensor.

1. Copy the package to the dedicated server or domain controller onto which you're installing the Defender for Identity sensor.

## Next steps

> [!div class="step-by-step"]
> [« Configure remote calls to SAM](remote-calls-sam.md)
> [Proxy configuration »](configure-proxy.md)
