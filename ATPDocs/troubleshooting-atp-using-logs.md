---
# required metadata

title: Troubleshooting Azure Threat Protection using the logs | Microsoft Docs
description: Describes how you can use the ATP logs to troubleshoot issues
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 3acfba05-c8d8-4e44-81d9-785ec36ff336

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



# Troubleshooting ATP using the ATP logs
The ATP logs provide insight into what each component of ATP is doing at any given point in time.

## ATP Standalone Sensor logs
In this section, every reference to the ATP Standalone Sensor is relevant also for the ATP Sensor. 

The ATP Standalone Sensor logs are located in a subfolder called **Logs** where ATP is installed; the default location is: **C:\Program Files\Microsoft Azure Threat Protection\**. In the default installation location, it can be found at: **C:\Program Files\Microsoft Azure Threat Protection\Gateway\Logs**.

The ATP Standalone Sensor has the following logs:

-   **Microsoft.Tri.Gateway.log** – This log contains everything that happens in the ATP Standalone Sensor (including resolution and errors). Its main use is getting the overall status of all operations in the chronological order in which they occurred.

-   **Microsoft.Tri.Gateway-Resolution.log** – This log contains the resolution details of the entities seen in traffic by the ATP Standalone Sensor. Its main use is investigating resolution issues of entities.

-   **Microsoft.Tri.Gateway-Errors.log** – This log contains just the errors that are caught by the ATP Standalone Sensor. Its main use is performing health checks and investigating issues that need to be correlated to specific times.

-   **Microsoft.Tri.Gateway-ExceptionStatistics.log** – This log groups all similar errors and exceptions, and measures their count.
    This file starts out  empty each time the ATP Standalone Sensor service starts and is updated every minute. Its main use is understanding if there are any new errors or issues with the ATP Standalone Sensor (because the errors are grouped it is easier to read and quickly understand if there are any new issues).
-	**Microsoft.Tri.Gateway.Updater.log** - This log is used for the gateway updater process, which is responsible for updating the ATP Standalone Sensor if configured to do so automatically. 
For the ATP Sensor, the gateway updater process is also responsible  for the resource limitations of the ATP Sensor.
-	**Microsoft.Tri.Gateway.Updater-ExceptionStatistics.log** - This log groups all similar errors and exceptions together, and measures their count. This file starts out empty each time the ATP Updater service starts and is updated every minute. It enables you to understand if there are any new errors or issues with the ATP Updater. The errors are grouped to make it easier to quickly understand if any new errors or issues are detected.

> [!NOTE]
> The first three log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed. By default, if more than 10 files from the same type already exist, the oldest are deleted.

## Azure ATP cloud service logs
The Azure ATP cloud service logs are located in a subfolder called **Logs**. In the default installation location, it can be found at: **C:\Program Files\Microsoft Azure Threat Protection\Center\Logs**".
> [!Note]
> The ATP console logs that were formerly under IIS logs are now located under Azure ATP cloud service logs.

The Azure ATP cloud service has the following logs:

-   **Microsoft.Tri.Center.log** – This log contains everything that happens in the Azure ATP cloud service, including detections and errors. Its main use is getting the overall status of all operations in the chronological order in which they occurred.

-   **Microsoft.Tri.Center-Detection.log** – This log contains just the detection details of the Azure ATP cloud service. Its main use is investigating detection issues.

-   **Microsoft.Tri.Center-Errors.log** – This log contains just the errors that are caught by the Azure ATP cloud service. Its main use is performing health checks and investigating issues that need to be correlated to specific times.

-   **Microsoft.Tri.Center-ExceptionStatistics.log** – This log groups all similar errors and exceptions, and measures their count.
    This file starts out empty each time the Azure ATP cloud service starts and is updated every minute. Its main use is understanding if there are any new errors or issues with the Azure ATP cloud service - because the errors are grouped it is easier to quickly understand if there is a new error or issue.

> [!NOTE]
> The first three log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed. By default, if more than 10 files from the same type already exist, the oldest are deleted.


## ATP Deployment logs
The ATP deployment logs are located in the temp directory for the user who installed the product. In the default installation location, it can be found at: **C:\Users\Administrator\AppData\Local\Temp** (or one directory above %temp%).

Azure ATP cloud service deployment logs:

-   **Microsoft Azure Threat Protection Center_YYYYMMDDHHMMSS.log** - This log lists the steps in the process of the deployment of the Azure ATP cloud service. Its main use is tracking the Azure ATP cloud service deployment process.

-   **Microsoft Azure Threat Protection Center_YYYYMMDDHHMMSS_0_MongoDBPackage.log** - This log lists the steps in the process of MongoDB deployment on the Azure ATP cloud service. Its main use is tracking the MongoDB deployment process.

-   **Microsoft Azure Threat Protection Center_YYYYMMDDHHMMSS_1_MsiPackage.log** - This log file lists the steps in the process of the deployment of the Azure ATP cloud service binaries. Its main use is tracking the deployment of the Azure ATP cloud service binaries.

ATP Standalone Sensor and ATP Sensor deployment logs:

-   **Microsoft Azure Threat Protection Gateway_YYYYMMDDHHMMSS.log** - This log lists the steps in the process of the deployment of the ATP Standalone Sensor. Its main use is tracking the ATP Standalone Sensor deployment process.

-   **Microsoft Azure Threat Protection Gateway_YYYYMMDDHHMMSS_001_MsiPackage.log** - This log file lists the steps in the process of the deployment of the ATP Standalone Sensor binaries. Its main use is tracking the deployment of the ATP Standalone Sensor binaries.


> [!NOTE] 
> In addition to the deployment logs mentioned here, there are other logs that begin with "Microsoft Azure Threat Protection" that can also provide additional information on the deployment process.


## See Also
- [ATP prerequisites](ata-prerequisites.md)
- [ATP capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
