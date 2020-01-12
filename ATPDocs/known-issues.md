---
# required metadata

title: Azure ATP Known Issues | Microsoft Docs
description: Describes current Known Issues in Azure ATP
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 02/25/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: feea1982-ba23-48be-a468-98d2586cf840


# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Azure ATP Known Issues

Azure ATP occasionally has engineering or feature limitations that may limit or change the way your organization uses Azure ATP services. Known Issue limitations that have no known workaround, or a work in progress status without a specific update timeline are described here. 

For Azure ATP known issues with known workarounds, see [Troubleshooting Azure ATP Known Issues](troubleshooting-atp-known-issues.md). To check the status of your Azure ATP tenant, visit the [Azure ATP Health Center](atp-health-center.md). 

## DNS reconnaissance alert
> [!div class="mx-tableFixed"] 

|Issue|Status|
|----|----|
The *DNS reconnaissance* security alert issue affects  customers by issuing repetitive False Positive **DNS reconnaissance alerts** from a single machine. If a spike of **DNS reconnaissance alerts** are seen generated from a single computer, close or delete these alerts until update 2.67 is deployed and resolves this issue. | Update 2.67 resolves this issue.|

## Suspected Brute Force attack (LDAP) Security Alert display
> [!div class="mx-tableFixed"] 

|Issue|Status|
|----|----|
The *Suspected Brute Force attack (LDAP)* security alert is not always displayed as expected. In certain scenarios, the alert description is displayed out of order.| Engineering is currently working on addressing this issue.| 

## AD groups with more than 1000 members have limited detail sync
> [!div class="mx-tableFixed"]  
> 
> |Issue|Status|
> |----|----|
> |Azure ATP does not support entity detail sync in AD groups with more than 1000 members per group. When investigating entities in groups with more than 1000 members, some entities may fail to sync or display details.|Engineering limitation. No known resolution.|

## Report downloads cannot contain more than 100,000 entries
> [!div class="mx-tableFixed"]  
> 
> |Issue|Status|
> |----|----|
> |Azure ATP does not support report downloads that contain more than 100,000 entries per report. Reports will render as incomplete if more than 100,000 entries are included.|Engineering limitation. No known resolution.|

## Closed issues

This group of known issues are now closed. Check the version number of the fix for reference.   
### Remote Code Execution attempts using Remote PowerShell commands or scripts are not detected when using Windows Server 2016 - v.2.57 (December 2, 2018)
> [!div class="mx-tableFixed"]  
> 
> |Issue|Status|
> |----|----|
> |Remote Code Execution attempts using Remote PowerShell commands are not currently detected on Sensor machines running Windows Server 2016. Related detections and resulting alerts are not available.|Engineering is currently working on addressing this issue and adding Windows Server 2016 support.|

## See Also

- [Troubleshooting Azure ATP Known Issues](troubleshooting-atp-known-issues.md)
- [Troubleshooting Azure ATP using logs](troubleshooting-atp-using-logs.md)
- [What's new in Azure ATP](atp-whats-new.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
