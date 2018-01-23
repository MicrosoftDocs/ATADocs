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
ms.assetid: b8ad5511-8893-4d1d-81ee-b9a86e378347

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



# Troubleshooting ATP using the ATP logs
The ATP logs provide insight into what each component of ATP is doing at any given point in time.

## ATP Gateway logs
In this section, every reference to the ATP Gateway is relevant also for the ATP Lightweight Gateway. 

The ATP Gateway logs are located in a subfolder called **Logs** where ATP is installed; the default location is: **C:\Program Files\Microsoft Azure Threat Protection\**. In the default installation location, it can be found at: **C:\Program Files\Microsoft Azure Threat Protection\Gateway\Logs**.

The ATP Gateway has the following logs:

-   **Microsoft.Tri.Gateway.log** – This log contains everything that happens in the ATP Gateway (including resolution and errors). Its main use is getting the overall status of all operations in the chronological order in which they occurred.

-   **Microsoft.Tri.Gateway-Resolution.log** – This log contains the resolution details of the entities seen in traffic by the ATP Gateway. Its main use is investigating resolution issues of entities.

-   **Microsoft.Tri.Gateway-Errors.log** – This log contains just the errors that are caught by the ATP Gateway. Its main use is performing health checks and investigating issues that need to be correlated to specific times.

-   **Microsoft.Tri.Gateway-ExceptionStatistics.log** – This log groups all similar errors and exceptions, and measures their count.
    This file starts out  empty each time the ATP Gateway service starts and is updated every minute. Its main use is understanding if there are any new errors or issues with the ATP Gateway (because the errors are grouped it is easier to read and quickly understand if there are any new issues).
-	**Microsoft.Tri.Gateway.Updater.log** - This log is used for the gateway updater process, which is responsible for updating the ATP Gateway if configured to do so automatically. 
For the ATP Lightweight Gateway, the gateway updater process is also responsible  for the resource limitations of the ATP Lightweight Gateway.
-	**Microsoft.Tri.Gateway.Updater-ExceptionStatistics.log** - This log groups all similar errors and exceptions together, and measures their count. This file starts out empty each time the ATP Updater service starts and is updated every minute. It enables you to understand if there are any new errors or issues with the ATP Updater. The errors are grouped to make it easier to quickly understand if any new errors or issues are detected.

> [!NOTE]
> The first three log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed. By default, if more than 10 files from the same type already exist, the oldest are deleted.

## ATP Center logs
The ATP Center logs are located in a subfolder called **Logs**. In the default installation location, it can be found at: **C:\Program Files\Microsoft Azure Threat Protection\Center\Logs**".
> [!Note]
> The ATP console logs that were formerly under IIS logs are now located under ATP Center logs.

The ATP Center has the following logs:

-   **Microsoft.Tri.Center.log** – This log contains everything that happens in the ATP Center, including detections and errors. Its main use is getting the overall status of all operations in the chronological order in which they occurred.

-   **Microsoft.Tri.Center-Detection.log** – This log contains just the detection details of the ATP Center. Its main use is investigating detection issues.

-   **Microsoft.Tri.Center-Errors.log** – This log contains just the errors that are caught by the ATP Center. Its main use is performing health checks and investigating issues that need to be correlated to specific times.

-   **Microsoft.Tri.Center-ExceptionStatistics.log** – This log groups all similar errors and exceptions, and measures their count.
    This file starts out empty each time the ATP Center service starts and is updated every minute. Its main use is understanding if there are any new errors or issues with the ATP Center - because the errors are grouped it is easier to quickly understand if there is a new error or issue.

> [!NOTE]
> The first three log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed. By default, if more than 10 files from the same type already exist, the oldest are deleted.


## ATP Deployment logs
The ATP deployment logs are located in the temp directory for the user who installed the product. In the default installation location, it can be found at: **C:\Users\Administrator\AppData\Local\Temp** (or one directory above %temp%).

ATP Center deployment logs:

-   **Microsoft Azure Threat Protection Center_YYYYMMDDHHMMSS.log** - This log lists the steps in the process of the deployment of the ATP Center. Its main use is tracking the ATP Center deployment process.

-   **Microsoft Azure Threat Protection Center_YYYYMMDDHHMMSS_0_MongoDBPackage.log** - This log lists the steps in the process of MongoDB deployment on the ATP Center. Its main use is tracking the MongoDB deployment process.

-   **Microsoft Azure Threat Protection Center_YYYYMMDDHHMMSS_1_MsiPackage.log** - This log file lists the steps in the process of the deployment of the ATP Center binaries. Its main use is tracking the deployment of the ATP Center binaries.

ATP Gateway and ATP Lightweight Gateway deployment logs:

-   **Microsoft Azure Threat Protection Gateway_YYYYMMDDHHMMSS.log** - This log lists the steps in the process of the deployment of the ATP Gateway. Its main use is tracking the ATP Gateway deployment process.

-   **Microsoft Azure Threat Protection Gateway_YYYYMMDDHHMMSS_001_MsiPackage.log** - This log file lists the steps in the process of the deployment of the ATP Gateway binaries. Its main use is tracking the deployment of the ATP Gateway binaries.


> [!NOTE] 
> In addition to the deployment logs mentioned here, there are other logs that begin with "Microsoft Azure Threat Protection" that can also provide additional information on the deployment process.


## See Also
- [ATP prerequisites](ata-prerequisites.md)
- [ATP capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
