---
title: Troubleshooting ATA using the ATA logs
ms.custom: na
ms.reviewer: na
ms.suite: na
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: b8ad5511-8893-4d1d-81ee-b9a86e378347
author: Rkarlin
---
# Troubleshooting ATA using the ATA logs
The ATA logs provide insight into what each component of ATA is doing at any giving point in time.

## ATA Gateway logs
The ATA Gateway logs are located in a subfolder called **Logs** . In the default installation location, it can be found at: **C:\Program Files\Microsoft Advanced Threat Analytics\Gateway\Logs**.

The ATA Gateway has the following logs:

-   **Microsoft.Tri.Gateway.log** – This log contains everything that happens in the ATA Gateway (including resolution and errors).

    Main use: Getting the overall status of all operations in the chronological order in which they occurred.

-   **Microsoft.Tri.Gateway-Resolution.log** – This log contains the resolution details of the entities seen in traffic by the ATA Gateway.

    Main use: Investigating resolution issues of entities.

-   **Microsoft.Tri.Gateway-Errors.log** – This log contains just the errors that are caught by the ATA Gateway.

    Main use: Performing health checks and investigating issues that need to be correlated to specific times.

-   **Microsoft.Tri.Gateway-ExceptionStatistics.log** – This log groups all similar errors and exceptions, and measures their count.
    This file starts out  empty each time the ATA Gateway service starts and is updated every minute.

    Main use: Understanding if there are any new errors or issues with the ATA Gateway  - because the errors are grouped it is easier to read and see if there is a new type of error or issue.

> [!NOTE]
> The first three log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed.

### ATA Center logs
The ATA Center logs are located in a subfolder called **Logs** . In the default installation location, it can be found at: **C:\Program Files\Microsoft Advanced Threat Analytics\Center\Logs**".

The ATA Center has the following logs:

-   **Microsoft.Tri.Center.log** – This log contains everything that happens in the ATA Center, including detections and errors.

    Main use: Getting the overall status of all operations in the chronological order in which they occurred.

-   **Microsoft.Tri.Center-Detection.log** – This log contains just the detection details of the ATA Center.

    Main use: Investigating detection issues.

-   **Microsoft.Tri.Center-Errors.log** – This log contains just the errors that are caught by the ATA Center.

    Main use: Performing health checks and investigating issues that need to be correlated to specific times.

-   **Microsoft.Tri.Center-ExceptionStatistics.log** – This log groups all similar errors and exceptions, and measures their count.
    This file starts out empty each time the ATA Center service starts and is updated every minute.

    Main use: Understanding if there are any new errors or issues with the ATA Center - because the errors are grouped it is easier to read and see if there is a new type of error or issue.

> [!NOTE]
> The first thee log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed.

### ATA Console logs
The ATA console logs (the management API logs) are located in a subfolder called **Logs** . In the default installation location, it can be found at: **C:\Program Files\Microsoft Advanced Threat Analytics\Center\Management\Logs**.

The ATA Console has the following logs:

-   **w3wp.log** – This log contains everything that happens in the management process (IIS).


-   **w3wp-Errors.log** – This log contains just the errors that are caught by the management process (IIS).


-   **8e75f9f1-ExceptionStatistics.log** – This log groups all similar errors and exceptions and measures their count.
    This file will start empty each time the gateway service will start and is updated every minute.

    Main use: Understanding if there are any new errors or issues with the ATA Center  - because the errors are grouped it is easier to read and see if there is a new type of error or issue.

> [!NOTE]
> The first two log files have a maximum size of up to 50 MB. When that size is reached, a new log file is opened and the previous one is renamed to "&lt;original file name&gt;-Archived-00000" where the number increments each time it is renamed.

### ATA Deployment logs
The ATA deployment logs (installation) are located in the temp directory for the user who installed the product. In the default installation location, it can be found at: **C:\Users\Administrator\AppData\Local\Temp** (or one directory above %temp%).

ATA Center deployment logs:

-   **Microsoft Advanced Threat Analytics Center_20150601104213.log** - This log lists the steps in the process of the deployment of the ATA Center. 
Main user: Tracking the ATA Center deployment process.

-   **Microsoft Advanced Threat Analytics Center_20150601104213_0_MongoDBPackage.log** - This log lists the steps in the process of MongoDB deployment on the ATA Center.
Main use: Tracking the MongoDB deployment process.

-   **Microsoft Advanced Threat Analytics Center_20150601104213_1_MsiPackage.log** - This log file lists the steps in the process of the deployment of the ATA Center binaries.
Main use: Tracking the deployment of the ATA Center binaries.

ATA Gateway deployment logs:

-   **Microsoft Advanced Threat Analytics Gateway_20151214014801.log** - This log lists the steps in the process of the deployment of the ATA Gateway. 
Main user: Tracking the ATA Gateway deployment process.

-   **Microsoft Advanced Threat Analytics Gateway_20151214014801_001_MsiPackage.log** - This log file lists the steps in the process of the deployment of the ATA Gateway binaries.
Main use: Tracking the deployment of the ATA Gateway binaries.

