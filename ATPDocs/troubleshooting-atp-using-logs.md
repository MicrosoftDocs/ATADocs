---
# required metadata

title: Troubleshooting Azure Advanced Threat Protection using the logs | Microsoft Docs
description: Describes how you can use the Azure ATP logs to troubleshoot issues
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 08/05/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: de796346-647d-48e1-970a-8f072e990f1e

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: 
ms.suite: 
#ms.tgt_pltfrm:
#ms.custom:

---



# Troubleshooting Azure Advanced Threat Protection (ATP) sensor using the ATP logs
The ATP logs provide insight into what each component of Azure ATP sensor is doing at any given point in time.


The Azure ATP logs are located in a subfolder called **Logs** where ATP is installed; the default location is: **C:\Program Files\Azure Advanced Threat Protection Sensor\\**. In the default installation location, it can be found at: **C:\Program Files\Azure Advanced Threat Protection Sensor\version number\Logs**.

The Azure ATP sensor has the following logs:

-   **Microsoft.Tri.Sensor.log** – This log contains everything that happens in the Azure ATP sensor (including resolution and errors). Its main use is getting the overall status of all operations in the chronological order in which they occurred.

-   **Microsoft.Tri.Sensor-Errors.log** – This log contains just the errors that are caught by the ATP sensor. Its main use is performing health checks and investigating issues that need to be correlated to specific times.

-	**Microsoft.Tri.Sensor.Updater.log** - This log is used for the sensor updater process, which is responsible for updating the ATP sensor if configured to do so automatically. 


> [!NOTE]
> The first three log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed. By default, if more than 10 files from the same type already exist, the oldest are deleted.

## Azure ATP Deployment logs
The Azure ATP deployment logs are located in the temp directory for the user who installed the product. In the default installation location, it can be found at: **C:\Users\Administrator\AppData\Local\Temp** (or one directory above %temp%).

Azure ATP sensor deployment logs:

-  **Azure Advanced Threat Protection Microsoft.Tri.Sensor.Deployment.Deployer_YYYYMMDDHHMMSS.log** - This log file provides the entire process of sensor deployment and can be found in the temp folder mentioned previously, or in C:\Windows\Temp. 

-   **Azure Advanced Threat Protection Sensor_YYYYMMDDHHMMSS.log** - This log lists the steps in the process of the deployment of the Azure ATP sensor. Its main use is tracking the Azure ATP sensor deployment process.

-   **Azure Advanced Threat Protection Sensor_YYYYMMDDHHMMSS_001_MsiPackage.log** - This log file lists the steps in the process of the deployment of the Azure ATP sensor binaries. Its main use is tracking the deployment of the Azure ATP sensor binaries.


> [!NOTE] 
> In addition to the deployment logs mentioned here, there are other logs that begin with "Azure Advanced Threat Protection" that can also provide additional information on the deployment process.


## See Also
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Azure ATP capacity planning](atp-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-forwarding.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
