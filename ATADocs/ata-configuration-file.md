---
# required metadata

title: Export and Import Advanced Threat Analytics Configuration
description: How to export and import the ATA configuration.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 9/04/2018
ms.topic: conceptual
ms.prod: advanced-threat-analytics
ms.technology:
ms.assetid: 1d27dba8-fb30-4cce-a68a-f0b1df02b977

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Export and Import the ATA Configuration

*Applies to: Advanced Threat Analytics version 1.9*

The configuration of ATA is stored in the "SystemProfile" collection in the database.
This collection is backed up every 4 hours by the ATA Center service to files called: **SystemProfile_*timestamp*.json**. The 300 most recent versions are stored.
This file is located in a subfolder called **Backup**. In the default ATA installed location it can be found here:  <em>C:\Program Files\Microsoft Advanced Threat Analytics\Center\Backup\SystemProfile_</em>timestamp<em>.json</em>. 

**Note**: It is recommended that you back up this file somewhere when making major changes to ATA.

It is possible to restore all the settings by running the following command:

`mongoimport.exe --db ATA --collection SystemProfile --file "<SystemProfile.json backup file>" --upsert`

## See Also
- [ATA architecture](ata-architecture.md)
- [ATA prerequisites](ata-prerequisites.md)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)

