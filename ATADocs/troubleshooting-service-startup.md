---
# required metadata

title: Troubleshooting Advanced Threat Analytics using the logs | Microsoft Docs
description: Describes how you can use the ATA logs to troubleshoot issues
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 5a65285c-d1de-4025-9bb4-ef9c20b13cfa

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Advanced Threat Analytics version 1.8*



# Troubleshooting ATA Center service startup

If your ATA Center does not start, perform the following troubleshooting procedure:

1.	Run the following Windows PowerShell command:
    `Get-Service Pla | Select Status`
to make sure the Performance counter service is running. If it's not, then it's a platform issue, and you need to make sure you get this service running again.
2.	If it was running, Try to restart it, and see if it resolves the issue:
    `Restart-Service Pla`
3.	Try to create a new data collector manually (any will suffice, even just collect machine CPU for example).
If it can start, the platform is probably fine. If not, it is still a platform issue.

4.	Try to manually recreate the ATA data collector, using an elevated prompt, running these commands:

        sc stop ATACenter
        logman stop "Microsoft ATA Center"
        logman export "Microsoft ATA Center" -xml c:\center.xml
        logman delete "Microsoft ATA Center"
        logman import "Microsoft ATA Center" -xml c:\center.xml
        logman start "Microsoft ATA Center"
        sc start ATACenter



## See Also
- [ATA prerequisites](ata-prerequisites.md)
- [ATA capacity planning](ata-capacity-planning.md)
- [Configure event collection](configure-event-collection.md)
- [Configuring Windows event forwarding](configure-event-collection.md#configuring-windows-event-forwarding)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
