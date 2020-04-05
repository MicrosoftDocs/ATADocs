---
# required metadata

title: Azure Advanced Threat Protection Monitored Activities Filter and Search
description: This article provides an overview of how to filter and search monitored activities using Azure ATP.
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 09/15/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: a546703b-d5a9-404d-9e87-125523bb8421

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---


# Azure ATP monitored activities search and filter 

> [!NOTE]
> The Azure ATP features explained on this page are also accessible using the new [portal](https://portal.cloudappsecurity.com).

Activities detected by Azure ATP on your network can be searched and filtered for easy drill-down and organization during your research and investigation into security alerts.  

From the Azure ATP timeline, select any entity in your network (DC, machine, or user) as the filter access point. Next, select to filter by the **Security Alert**, **Activity** type, or any combination. Once the filter is applied, the threat timeline of the entity is updated with the filtered information. Your filtered alerts and activities can also be downloaded to continue your investigation or tracking in other tools. 

![Filter alerts and activities](./media/activities-filter.png)

To filter alerts and activities:
 1. Select the entity to investigate from the Azure ATP timeline. 
 2. Click **Filter by**, then select the alerts and/or activities to filter. 
 3. Click **Apply**. The entity timeline is updated according to the filters you selected. 
 4. To download the filtered activities, click **Download activities** and select the date range for your download report. 
 5. To reset the entity timeline to display all alerts and activities, click **Reset** or close the filter. 


## See Also
- [Investigating entities](investigate-entity.md)
- [Health alerts](health-alerts.md)
- [Working with Security Alerts](working-with-suspicious-activities.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)
