---
# required metadata

title: Troubleshooting Azure Threat Protection service startup | Microsoft Docs
description: Describes how you can troubleshoot ATP startup issues
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 12/20/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 36bcc9c5-2790-4af2-8da5-6b1e788c96d8

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



# Troubleshooting service startup

## Troubleshooting Azure ATP cloud service startup

If your Azure ATP cloud service does not start, perform the following troubleshooting procedure:

1.	Run the following Windows PowerShell command:
    `Get-Service Pla | Select Status`
to make sure the Performance counter service is running. If it's not, then it's a platform issue, and you need to make sure you get this service running again.
2.	If it was running, Try to restart it, and see if it resolves the issue:
    `Restart-Service Pla`
3.	Try to create a new data collector manually (any will suffice, even just collect machine CPU for example).
If it can start, the platform is probably fine. If not, it is still a platform issue.

4.	Try to manually recreate the ATP data collector, using an elevated prompt, running these commands:

        sc stop ATACenter
        logman stop "Microsoft Azure ATP cloud service"
        logman export "Microsoft Azure ATP cloud service" -xml c:\center.xml
        logman delete "Microsoft Azure ATP cloud service"
        logman import "Microsoft Azure ATP cloud service" -xml c:\center.xml
        logman start "Microsoft Azure ATP cloud service"
        sc start ATACenter

## Troubleshooting ATP Sensor startup

**Symptom**

Your ATP Standalone Sensor does not start and you get this error:<br></br>
*System.Net.Http.HttpRequestException: Response status code does not indicate success: 500 (Internal Server Error)*

**Description**

This happens because as part of the Sensor installation process, ATP allocates a CPU threshold that enables the Sensor to utilize CPU with a buffer of 15%. If you have independently set a threshold using the registry key: this conflict will prevent the Sensor from starting. 

**Resolution**

1. Under the registry keys, if there is a DWORD value called **Disable Performance Counters** make sure it is set to **0**:
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfOS\Performance\`
    `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfProc\Performance`
 
2. Then restart the Pla service. The ATP Sensor will automatically detect the change and restart the service.


## See Also
- [ATP prerequisites](ata-prerequisites.md)
- [ATP capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
