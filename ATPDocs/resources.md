---
title: List of helpful resources for Microsoft Defender for Identity
description: This article provides a list of helpful resources for Microsoft Defender for Identity
ms.date: 10/27/2020
ms.topic: conceptual
---

# Microsoft Defender for Identity readiness guide

This article provides you with a readiness roadmap list of resources that help you get started with [!INCLUDE [Product long](includes/product-long.md)].

## Understanding Microsoft Defender for Identity

[!INCLUDE [Product long](includes/product-long.md)] is a cloud service that helps identify and protect your enterprise from multiple types of advanced targeted cyber-attacks and insider threats.

To learn more about [!INCLUDE [Product short](includes/product-short.md)]:

- [[!INCLUDE [Product short](includes/product-short.md)] overview](what-is.md)
- [[!INCLUDE [Product short](includes/product-short.md)] introductory video (25 minutes)- Full](https://www.youtube.com/watch?v=EGY2m8yU_KE)
- [[!INCLUDE [Product short](includes/product-short.md)] deep dive video (75 minutes)- Full](https://www.youtube.com/watch?v=QXZIfH0wP3Q)

## Deployment decisions

[!INCLUDE [Product short](includes/product-short.md)] is comprised of a Cloud service residing in Azure, and integrated sensors that can be installed on domain controllers. If you are using physical servers, capacity planning is critical. Get help from the sizing tool to allocate space for your sensors:

- [[!INCLUDE [Product short](includes/product-short.md)] sizing tool](https://aka.ms/aatpsizingtool) - The sizing tool automates collection of the amount of traffic [!INCLUDE [Product short](includes/product-short.md)] monitors. It automatically provides supportability and resource recommendations for sensors.
- [[!INCLUDE [Product short](includes/product-short.md)] capacity planning guidance](capacity-planning.md)

## Deploy Defender for Identity

Use these resources to help you set up [!INCLUDE [Product short](includes/product-short.md)], connect to Active Directory, download the sensor package, set up event collection, and optionally integrate with your VPN, and set up honeytoken accounts and exclusions.

- [Try [!INCLUDE [Product short](includes/product-short.md)] (part of EMS E5)](https://go.microsoft.com/fwlink/p/?LinkID=2077047)  The trial is valid for 90 days.
- [[!INCLUDE [Product short](includes/product-short.md)] Set up](install-step1.md) Follow these steps to deploy [!INCLUDE [Product short](includes/product-short.md)] in your environment.
- [Integrate [!INCLUDE [Product short](includes/product-short.md)] with Microsoft Defender for Endpoint](integrate-mde.md)

## Defender for Identity settings

When creating your [!INCLUDE [Product short](includes/product-short.md)] instance, the basic settings necessary are configured automatically. There are several additional configurable settings in [!INCLUDE [Product short](includes/product-short.md)] to improve detection and alert accuracy for your environment, such as VPN integration, SAM required permissions, and advanced audit policy settings.

- [VPN integration](install-step6-vpn.md)
- [SAM-R required permissions](install-step8-samr.md)
- [Audit policy settings](configure-windows-event-collection.md) – Audit your domain controller health before and after a [!INCLUDE [Product short](includes/product-short.md)] deployment.

## Work with Defender for Identity

After [!INCLUDE [Product short](includes/product-short.md)] is up and running, view security alerts in the [!INCLUDE [Product short](includes/product-short.md)] portal activity timeline. The activity timeline is the default landing page after logging in to the [!INCLUDE [Product short](includes/product-short.md)] portal. By default, all open security alerts are shown on the activity timeline. You can also see the severity assigned to each alert. Investigate each alert by drilling down into the entities (computers, devices, users) to open their profile pages with more information. Lateral movement paths show potential moves that can be made in your network and sensitive users at risk. Investigate and remediate exposure using the lateral movement path detection graphs. These resources help you work with [!INCLUDE [Product short](includes/product-short.md)]'s security alerts:

- [[!INCLUDE [Product short](includes/product-short.md)] security alert guide](suspicious-activity-guide.md) Learn to triage and take the next steps with your [!INCLUDE [Product short](includes/product-short.md)] detections.
- [[!INCLUDE [Product short](includes/product-short.md)] lateral movement paths](use-case-lateral-movement-path.md)
- [Tag groups as sensitive](manage-sensitive-honeytoken-accounts.md) Gain visibility into credential exposure on sensitive security groups.

## Security best practices

- [[!INCLUDE [Product short](includes/product-short.md)] Frequently Asked Questions](technical-faq.yml) - This article provides a list of frequently asked questions about [!INCLUDE [Product short](includes/product-short.md)] and provides insight and answers.

## Community resources

Blog: [[!INCLUDE [Product short](includes/product-short.md)] blog](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/bg-p/MicrosoftSecurityandCompliance/label-name/Microsoft%20Defender%20for%20Identity)

Public Community: [[!INCLUDE [Product short](includes/product-short.md)] Tech Community](https://aka.ms/AatpCom)

Private Community: [[!INCLUDE [Product short](includes/product-short.md)] Yammer Group](https://www.yammer.com/azureadvisors/#/threads/inGroup?type=in_group&feedId=9386893&view=all&preserve-view=true)

## See also

- [Working with sensitive accounts](manage-sensitive-honeytoken-accounts.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
