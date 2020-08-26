---
# required metadata

title: Advanced Threat Analytics to Azure Advanced Threat Protection move
description: Learn how to move an existing Advanced Threat Analytics installation to Azure ATP.
keywords:
author: shsagir
ms.author: shsagir
manager: shsagir
ms.date: 07/13/2020
ms.topic: how-to
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: e734e382-c4b1-43ca-9a8d-96c91daf2578

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Advanced Threat Analytics (ATA) to Azure Advanced Threat Protection (Azure ATP)

Use this guide to move from an existing ATA installation to the Azure Advanced Threat Protection (Azure ATP) service. The guide explains Azure ATP prerequisites and requirements, and details how to plan and then complete your move. Validation steps and tips to take advantage of the latest threat protection and security solutions with Azure ATP after installation are also included.

To learn more about the differences between ATA and Azure ATP, see the [Azure ATP frequently asked questions](./atp-technical-faq.md#what-is-azure-atp).

In this guide you will:

> [!div class="checklist"]
>
> - Review and confirm Azure ATP service prerequisites
> - Document your existing ATA configuration
> - Plan your move
> - Set up and configure your Azure ATP  service
> - Perform post move checks and verification
> - Decommission ATA after completing the move

> [!NOTE]
> Moving to Azure ATP from ATA is possible from any ATA version. However, as data cannot be moved from ATA to Azure ATP, it is recommended to retain your ATA Center data and alerts required for ongoing investigations until all ATA alerts are closed or remediated.

## Prerequisites

- An Azure Active Directory tenant with at least one global/security administrator is required to create an Azure ATP instance. Each Azure ATP instance supports a multiple Active Directory forest boundary and Forest Functional Level (FFL) of Windows 2003 and above.

- Azure ATP requires .Net Framework 4.7 or later and may require a domain controller (restart) if your current .Net Framework version is not 4.7 or later.

- Make sure your domain controllers meet all the [Azure ATP sensor requirements](./atp-prerequisites.md#azure-atp-sensor-requirements) and your environment meets all [Azure ATP requirements](./atp-prerequisites.md).

- Validate that all domain controllers you plan to use have sufficient internet access to the Azure ATP service. Check and confirm your domain controllers meet the [Azure ATP proxy configuration requirements](./configure-proxy.md).

> [!NOTE]
> This migration guide is designed for Azure ATP sensors only. For more information, see [choosing the right sensor for your deployment](./atp-capacity-planning.md#choosing-the-right-sensor-type-for-your-deployment).

## Plan

Make sure to gather the following information before starting your move:

1. Account details for your [Directory Services](./install-atp-step2.md) account.
1. Syslog notification [settings](./setting-syslog.md).
1. Email [notification details](./notifications.md).
1. ATA roles group membership
1. VPN integration
1. Alert exclusions
    - Exclusions are not transferable from ATA to Azure ATP, so details of each exclusion are required to [replicate the exclusions in Azure ATP](./excluding-entities-from-detections.md).
1. Account details for HoneyToken accounts.
    - If you don't already have dedicated HoneyToken accounts, learn more about [HoneyTokens in Azure ATP](./install-atp-step7.md) and create new accounts to use for this purpose.
1. Complete list of all entities (computers, groups, users) you wish to manually tag as Sensitive entities.
    - Learn more about the importance of [Sensitive entities](./sensitive-accounts.md) in Azure ATP.
1. Report scheduling [details](./reports.md) (list of reports and scheduled timing).

> [!NOTE]
> Do not uninstall the ATA Center until all ATA Gateways are removed. Uninstalling the ATA Center with ATA Gateways still running leaves your organization exposed with no threat protection.

## Move

Complete your move to Azure ATP in two easy steps:

### Step 1: Create and install Azure ATP instance and sensors

1. [Create your new Azure ATP instance](./install-atp-step1.md)

2. Uninstall the ATA Lightweight Gateway on all domain controllers.

3. Install the Azure ATP Sensor on all domain controllers:
    - [Download the Azure ATP sensor files](./install-atp-step3.md).
    - [Retrieve your Azure ATP Access Key](./install-atp-step3.md#download-the-setup-package).
    - [Install Azure ATP sensors on your domain controllers](./install-atp-step4.md).

### Step 2: Configure and validate Azure ATP instance

- [Configure the Sensor](./install-atp-step5.md)

> [!NOTE]
> Certain tasks in the following list cannot be completed before installing Azure ATP sensors and then completing an initial sync, such as selecting entities for manual **Sensitive** tagging. Allow up to 2 hours for the initial sync to be completed.

#### Configuration

Sign in to the Azure ATP portal and complete the following configuration tasks.

| Step    | Action | Status |
|--------------|------------|------------------|
| 1  | Set [delayed updates on a selection of domain controllers](./sensor-update.md) | - [ ] |
| 2  | [Directory Services](./install-atp-step2.md) account details| - [ ] |
| 3  | Configure [Syslog notifications](./setting-syslog.md) | - [ ] |
| 4  | [Integrate VPN](./install-atp-step6-vpn.md) information| - [ ] |
| 5  | Configure [WDATP integration](./integrate-wd-atp.md)| - [ ] |
| 6  | Set [HoneyTokens](./install-atp-step7.md) accounts| - [ ] |
| 7  | Tag [Sensitive entities](./sensitive-accounts.md)| - [ ] |
| 8  | Create [Security alert exclusions](./excluding-entities-from-detections.md)| - [ ] |
| 9 | [Email notification toggles](./notifications.md) | - [ ] |
| 10  | [Schedule report settings](./reports.md) (list of reports and scheduled timing)| - [ ] |
| 11  | Configure [Role based permissions](./atp-role-groups.md) | - [ ] |
| 12  | [SIEM notification configuration (IP address)](./configure-event-collection.md#siemsyslog)| - [ ] |

#### Validation

Within the Azure ATP portal:

- Review any [health alerts](./atp-health-center.md) for signs of service issues.
- Review Azure ATP [Sensor error logs](./troubleshooting-atp-using-logs.md) for any unusual errors.

## After the move

This section of the guide explains the actions that can be performed after completing your move.

> [!NOTE]
> Import of existing security alerts from ATA to ATP are not supported. Make sure to record or remediate all existing ATA alerts before decommissioning the ATA Center.

- **Decommission the ATA Center**  
  - To reference the ATA Center data after the move, we recommend keeping the center data online for a period of time. After decommissioning the ATA Center, the number of resources can typically be reduced, especially if the resources are a Virtual Machine.

- **Back up Mongo DB**  
  - If you wish to keep the ATA data indefinitely, [back up Mongo DB](/advanced-threat-analytics/ata-database-management#backing-up-the-ata-database).

## Mission accomplished

Congratulations! Your move from ATA to Azure ATP is complete.

## Next steps

Learn more about [Azure ATP](./what-is-atp.md) features, functionality, and [security alerts](./understanding-security-alerts.md).

## Join the Community

Do you have more questions, or an interest in discussing Azure ATP and related security with others? Join the [Azure ATP Community](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection) today!