---
# required metadata

title: List of helpful resources for Azure Advanced Threat Protection | Microsoft Docs
description: This article provides a list of helpful resources for Azure ATP 
keywords:
author: mlottner
ms.author: mlottner
manager: barbkess
ms.date: 1/24/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
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



# Azure ATP readiness guide

This article provides you with a readiness roadmap list of resources that help you get started with Azure Advanced Threat Protection. 

## Understanding Azure ATP

Azure Advanced Threat Protection (ATP) is a cloud service that helps identify and protect your enterprise from multiple types of advanced targeted cyber-attacks and insider threats.
 
To learn more about Azure ATP: 
- [Azure ATP overview](what-is-atp.md)
- [Azure ATP introductory video (25 minutes)- Full](https://www.youtube.com/watch?v=EGY2m8yU_KE)
- [Azure ATP deep dive video (75 minutes)- Full](https://www.youtube.com/watch?v=QXZIfH0wP3Q)

## Deployment decisions

Azure ATP is comprised of a Cloud service residing in Azure, and integrated sensors that can be installed on domain controllers or standalone sensors on dedicated servers. Before you get Azure ATP up and running, it's important to choose the type of sensors that best suit your deployment and needs. Azure ATP integrated sensors (Azure ATP sensors) provide enhanced security, lower operational costs and easier deployment than Azure ATP standalone sensors. Azure ATP standalone sensors require physical hardware, additional configuration steps and heavier operational costs. <br>If you are using physical servers, capacity planning is critical. Get help from the sizing tool to allocate space for your sensors: 
- [Azure ATP sizing tool](http://aka.ms/aatpsizingtool) - The sizing tool automates collection of the amount of traffic Azure ATP monitors. It automatically provides supportability and resource recommendations for sensors. 
- [ATP capacity planning guidance](atp-capacity-planning.md)

## Deploy Azure ATP

Use these resources to help you set up Azure ATP, connect to Active Directory, download the sensor package, set up event collection, and optionally integrate with your VPN, and set up honeytoken accounts and exclusions. 
- [Try Azure ATP (part of EMS E5)](http://aka.ms/aatptrial)  The trial is valid for 90 days.
- [Azure ATP Set up](install-atp-step1.md) Follow these steps to deploy Azure ATP in your environment.
- [Integrate Azure ATP with Windows Defender ATP](integrate-wd-atp.md)

## Azure ATP settings

When creating your Azure ATP instance, the basic settings necessary are configured automatically. There are several additional configurable settings in Azure ATP to improve detection and alert accuracy for your environment, such as VPN integration, SAM required permissions, and advanced audit policy settings. 

- [VPN integration](install-atp-step6-vpn.md)
- [SAM-R required permissions](install-atp-step8-samr.md)
- [Audit policy settings](atp-advanced-audit-policy.md) – Audit your domain controller health before and after an ATP deployment. 

## Work with Azure ATP

After Azure ATP is up and running, view security alerts in the Azure ATP portal activity timeline. The activity timeline is the default landing page after logging in to the Azure ATP portal. By default, all open security alerts are shown on the activity timeline. You can also see the severity assigned to each alert. Investigate each alert by drilling down into the entities (computers, devices, users) to open their profile pages with more information. Lateral movement paths show potential moves that can be made in your network and sensitive users at risk. Investigate and remediate exposure using the lateral movement path detection graphs. These resources help you work with Azure ATP's security alerts: 

- [Azure ATP security alert guide](suspicious-activity-guide.md) Learn to triage and take the next steps with your Azure ATP detections.
- [Azure ATP lateral movement paths](use-case-lateral-movement-path.md)
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
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
