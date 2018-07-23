---
# required metadata

title: List of helpful resources for Azure Advanced Threat Protection | Microsoft Docs
description: This article provides a list of helpful resources for Azure ATP 
keywords:
author: mlottner
ms.author: mlottner
manager: mbaldwin
ms.date: 7/23/2018
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: 34dc152c-6b7f-4128-93fe-aad56c282730

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*



# Azure ATP readiness guide

This article provides you with a readiness roadmap that gives you with a list of resources that assist you to get started with Azure Advanced Threat Analytics. 

## Understanding Azure ATP

Azure Advanced Threat Protection (ATP) is a cloud service that helps protect your enterprise from multiple types of advanced targeted cyber-attacks and insider threats. 
Use the following resources to learn more about Azure ATP: 
- [Azure ATP overview](what-is-atp.md)
- [Azure ATP introductory video - Full](https://www.youtube.com/watch?v=KX-xpFc0sBw) 

## Deployment decisions

Azure ATP is comprised of a Cloud Service residing in Azure, and sensors that can be installed on a domain controller or on dedicated servers. Before you get Azure ATP up and running, it's important to choose what type of sensors better suit your deployment.<br>If you are using physical servers, you should plan capacity. You can get help from the sizing tool to allocate space for your sensors: 
- [Azure ATP sizing tool](http://aka.ms/aatpsizingtool) - The sizing tool automates collection of the amount of traffic Azure ATP monitors. It automatically provides supportability and resource recommendations for sensors. 
- [ATA capacity planning guidance](atp-capacity-planning.md)

## Deploy Azure ATP

These resources will help you set up Azure ATP, connect to Active Directory, download the sensor package, set up event collection and optionally integrate with your VPN and set up honeytoken accounts and exclusions. 
- [Try Azure ATP (part of EMS E5)](http://aka.ms/aatptrial)  The trial is valid for 90 days.
- [Deployment guide](install-atp-step1.md)  Deploy Azure ATP in your environment following these steps.
- [Integrate Azure ATP with Windows Defender ATP](integrate-wd-atp.md)

## Azure ATP settings

The basic necessary settings in Azure ATP are configured when creating the workspace. However, there are several other settings that you can configure to fine-tune Azure ATP that make detections more accurate for your environment, such as SIEM integration and audit settings. 

- [Azure ATP general documentation](what-is-atp.md)
- [Audit settings](https://blogs.technet.microsoft.com/positivesecurity/2017/08/18/ata-auditing-auditpol-advanced-audit-settings-enforcement-lightweight-gateway-service-discovery/) – Audit your domain controller health before and after an ATA deployment. 

## Work with Azure ATP

After Azure ATP is up and running, you will be able to view suspicious activities that are detected in the activity time line. This is the default landing page you are taken to when you log in to the Azure ATP portal. By default, all open suspicious activities are shown on the attack time line. You can also see the severity assigned to each activity. Investigate each suspicious activity by drilling down into the entities (computers, devices, users) to open their profile pages that provide more information. These resources will help you work with Azure ATP's suspicious activities: 

- [Azure ATP suspicious activity guide](suspicious-activity-guide.md) Learn to triage and take the next steps with your Azure ATP detections.
- [Tag groups as sensitive](sensitive-accounts.md) Gain visibility into credential exposure on sensitive security groups.

## Security best practices

- [Azure ATP Frequently Asked Questions](atp-technical-faq.md) - This article provides a list of frequently asked questions about Azure ATP and provides insight and answers. 
## Community resources

Blog: [Azure ATP blog](https://aka.ms/aatpblog)

Public Community: [Azure ATP Tech Community](https://aka.ms/AatpCom)

Private Community: [Azure ATP Yammer Group](https://www.yammer.com/azureadvisors/#/threads/inGroup?type=in_group&feedId=9386893&view=all)

Channel 9: [Microsoft Security Channel 9 page](https://channel9.msdn.com/Shows/Microsoft-Security/)



## See Also

- [Working with sensitive accounts](sensitive-accounts.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)