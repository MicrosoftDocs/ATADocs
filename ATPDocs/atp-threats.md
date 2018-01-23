---
# required metadata

title: What threats does Azure Threat Protection detect? | Microsoft Docs
description: Lists the threats that Azure Threat Protection detects 
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 283e7b4e-996a-4491-b7f6-ff06e73790d2

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

# What threats does ATP look for?

ATP provides detection for the following various phases of an advanced attack: reconnaissance, credential compromise, lateral movement, privilege escalation, domain dominance, and others. These detections are aimed at detecting advanced attacks and insider threats before they cause damage to your organization.
The detection of each phase results in several suspicious activities relevant for the phase in question, where each suspicious activity correlates to different flavors of possible attacks.
These phases in the kill-chain where ATP currently provides detections are highlighted in the following image:

![ATP focus on lateral activity in attack kill chain](media/attack-kill-chain-small.jpg)


For more information, see [Working with suspicious activities](working-with-suspicious-activities.md) and the [ATP suspicious activity guide](suspicious-activity-guide.md).


## What's next?

-   For more information about how ATP fits into your network: [ATP architecture](ata-architecture.md)

-   To get started deploying ATP: [Install ATP](install-ata-step1.md)


## See Also
[Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
