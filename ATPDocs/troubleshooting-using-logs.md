---
title: Troubleshooting Microsoft Defender for Identity using the logs
description: Describes how you can use the Microsoft Defender for Identity logs to troubleshoot issues
ms.date: 10/27/2020
ms.topic: how-to
---

# Troubleshooting Microsoft Defender for Identity sensor using the Defender for Identity logs

The [!INCLUDE [Product short](includes/product-short.md)] logs provide insight into what each component of [!INCLUDE [Product long](includes/product-long.md)] sensor is doing at any given point in time.

The [!INCLUDE [Product short](includes/product-short.md)] logs are located in a subfolder called **Logs** where [!INCLUDE [Product short](includes/product-short.md)] is installed; the default location is: **C:\Program Files\Azure Advanced Threat Protection Sensor\\**. In the default installation location, it can be found at: **C:\Program Files\Azure Advanced Threat Protection Sensor\version number\Logs**.

The [!INCLUDE [Product short](includes/product-short.md)] sensor has the following logs:

- **Microsoft.Tri.Sensor.log** – This log contains everything that happens in the [!INCLUDE [Product short](includes/product-short.md)] sensor (including resolution and errors). Its main use is getting the overall status of all operations in the chronological order in which they occurred.

- **Microsoft.Tri.Sensor-Errors.log** – This log contains just the errors that are caught by the [!INCLUDE [Product short](includes/product-short.md)] sensor. Its main use is performing health checks and investigating issues that need to be correlated to specific times.

- **Microsoft.Tri.Sensor.Updater.log** - This log is used for the sensor updater process, which is responsible for updating the [!INCLUDE [Product short](includes/product-short.md)] sensor if configured to do so automatically.

> [!NOTE]
> The first three log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed. By default, if more than 10 files from the same type already exist, the oldest are deleted.

## Defender for Identity Deployment logs

The [!INCLUDE [Product short](includes/product-short.md)] deployment logs are located in the temp directory of the user who installed the product. It will usually be found at **%USERPROFILE%\AppData\Local\Temp**. If it was deployed by a service, it might be found at **C:\Windows\Temp**.

[!INCLUDE [Product short](includes/product-short.md)] sensor deployment logs:

- **Azure Advanced Threat Protection Microsoft.Tri.Sensor.Deployment.Deployer_YYYYMMDDHHMMSS.log** - This log file provides the entire process of sensor deployment and can be found in the temp folder mentioned previously.

- **Azure Advanced Threat Protection Sensor_YYYYMMDDHHMMSS.log** - This log lists the steps in the process of the deployment of the [!INCLUDE [Product short](includes/product-short.md)] sensor. Its main use is tracking the [!INCLUDE [Product short](includes/product-short.md)] sensor deployment process.

- **Azure Advanced Threat Protection Sensor_YYYYMMDDHHMMSS_001_MsiPackage.log** - This log file lists the steps in the process of the deployment of the [!INCLUDE [Product short](includes/product-short.md)] sensor binaries. Its main use is tracking the deployment of the [!INCLUDE [Product short](includes/product-short.md)] sensor binaries.

> [!NOTE]
> In addition to the deployment logs mentioned here, there are other logs that begin with "Azure Advanced Threat Protection" that can also provide additional information on the deployment process.

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md)
- [[!INCLUDE [Product short](includes/product-short.md)] capacity planning](capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
