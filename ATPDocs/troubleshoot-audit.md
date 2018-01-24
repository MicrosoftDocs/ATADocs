---
# required metadata

title: Working with ATP audit logs | Microsoft Docs
description: This article describes how to work with ATP audit logs in the Windows Event Log.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 35191bfc-b748-4811-b57d-1251d0bb9853

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

# Working with ATP audit logs

The ATP audit logs are kept in the Windows Event Logs under **Applications and Services** and then **Microsoft ATP** both on the Azure ATP cloud service and ATP Standalone Sensor machines.

The Azure ATP cloud service audit log contains:
-	Suspicious activity information
-	Monitoring alerts (health page)
-	ATP Console logins
-	All configuration changes*

The ATP Standalone Sensor audit log contains:
-	Gateway configuration changes* 

(All ATP Standalone Sensor configuration changes are configured on the Azure ATP cloud service but are still audited on the Gateway machine itself.)

*The configuration change audit log contains both the previous configuration and the new configuration.


## See Also
- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
