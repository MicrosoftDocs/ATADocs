---
title: Advanced Threat Analytics to Microsoft Defender for Identity move
description: Learn how to move an existing Advanced Threat Analytics installation to Microsoft Defender for Identity.
ms.date: 06/23/2022
ms.topic: how-to
---

# Advanced Threat Analytics (ATA) to Microsoft Defender for Identity

> [!NOTE]
> The final release of ATA is [generally available](https://support.microsoft.com/help/4568997/update-3-for-microsoft-advanced-threat-analytics-1-9). ATA ended Mainstream Support on January 12, 2021. Extended Support will continue until January 2026. For more information, read [our blog](https://techcommunity.microsoft.com/t5/microsoft-security-and/end-of-mainstream-support-for-advanced-threat-analytics-january/ba-p/1539181).

Use this guide to move from an existing ATA installation to the ([!INCLUDE [Product long](includes/product-long.md)]) service. The guide explains [!INCLUDE [Product short](includes/product-short.md)] prerequisites and requirements, and details how to plan and then complete your move. Validation steps and tips to take advantage of the latest threat protection and security solutions with [!INCLUDE [Product short](includes/product-short.md)] after installation are also included.

To learn more about the differences between ATA and [!INCLUDE [Product short](includes/product-short.md)], see the [[!INCLUDE [Product short](includes/product-short.md)] frequently asked questions](technical-faq.yml).

In this guide you will:

> [!div class="checklist"]
>
> - Review and confirm [!INCLUDE [Product short](includes/product-short.md)] service prerequisites
> - Document your existing ATA configuration
> - Plan your move
> - Set up and configure your [!INCLUDE [Product short](includes/product-short.md)]  service
> - Perform post move checks and verification
> - Decommission ATA after completing the move

> [!NOTE]
> Moving to [!INCLUDE [Product short](includes/product-short.md)] from ATA is possible from any ATA version. However, as data cannot be moved from ATA to [!INCLUDE [Product short](includes/product-short.md)], it is recommended to retain your ATA Center data and alerts required for ongoing investigations until all ATA alerts are closed or remediated.

## Prerequisites

- An Azure Active Directory tenant with at least one global/security administrator is required to create a [!INCLUDE [Product short](includes/product-short.md)] instance. Each [!INCLUDE [Product short](includes/product-short.md)] instance supports a multiple Active Directory forest boundary and Forest Functional Level (FFL) of Windows 2003 and above.

- [!INCLUDE [Product short](includes/product-short.md)] requires .Net Framework 4.7 or later and may require a domain controller restart if your current .Net Framework version is not 4.7 or later.

- Make sure your domain controllers meet all the [[!INCLUDE [Product short](includes/product-short.md)] sensor requirements](prerequisites.md#defender-for-identity-sensor-requirements) and your environment meets all [[!INCLUDE [Product short](includes/product-short.md)] requirements](prerequisites.md).

- Validate that all domain controllers you plan to use have sufficient internet access to the [!INCLUDE [Product short](includes/product-short.md)] service. Check and confirm your domain controllers meet the [[!INCLUDE [Product short](includes/product-short.md)] proxy configuration requirements](configure-proxy.md).

> [!NOTE]
> This migration guide is designed for [!INCLUDE [Product short](includes/product-short.md)] sensors only.

## Plan

Make sure to gather the following information before starting your move:

1. Account details for your [Directory Services](directory-service-accounts.md) account.
1. Syslog notification [settings](setting-syslog.md).
1. Email [notification details](notifications.md).
1. ATA roles group membership
1. VPN integration
1. Alert exclusions
    - Exclusions are not transferable from ATA to [!INCLUDE [Product short](includes/product-short.md)], so details of each exclusion are required to [replicate the exclusions in [!INCLUDE [Product short](includes/product-short.md)]](excluding-entities-from-detections.md).
1. Account details for honeytoken accounts.
    - If you don't already have dedicated honeytoken accounts, learn more about [honeytokens in [!INCLUDE [Product short](includes/product-short.md)]](manage-sensitive-honeytoken-accounts.md) and create new accounts to use for this purpose.
1. Complete list of all entities (computers, groups, users) you wish to manually tag as Sensitive entities.
    - Learn more about the importance of [Sensitive entities](manage-sensitive-honeytoken-accounts.md) in [!INCLUDE [Product short](includes/product-short.md)].
1. Report scheduling [details](reports.md) (list of reports and scheduled timing).

> [!NOTE]
> Do not uninstall the ATA Center until all ATA Gateways are removed. Uninstalling the ATA Center with ATA Gateways still running leaves your organization exposed with no threat protection.

## Move

Complete your move to [!INCLUDE [Product short](includes/product-short.md)] in two easy steps:

### Step 1: Create and install Defender for Identity instance and sensors

1. [Create your new [!INCLUDE [Product short](includes/product-short.md)] instance](deploy-defender-identity.md#start-using-microsoft-365-defender)

1. Uninstall the ATA Lightweight Gateway on all domain controllers.

1. Install the [!INCLUDE [Product short](includes/product-short.md)] Sensor on all domain controllers:
    - [Download the [!INCLUDE [Product short](includes/product-short.md)] sensor files](download-sensor.md) and retrieve the access key.
    - [Install [!INCLUDE [Product short](includes/product-short.md)] sensors on your domain controllers](install-sensor.md).

### Step 2: Configure and validate Defender for Identity instance

- [Configure the Sensor](configure-sensor-settings.md)

> [!NOTE]
> Certain tasks in the following list cannot be completed before installing [!INCLUDE [Product short](includes/product-short.md)] sensors and then completing an initial sync, such as selecting entities for manual **Sensitive** tagging. Allow up to 2 hours for the initial sync to be completed.

#### Validation

In the Microsoft 365 Defender portal:

- Review any [health alerts](health-center.md) for signs of service issues.
- Review [!INCLUDE [Product short](includes/product-short.md)] [Sensor error logs](troubleshooting-using-logs.md) for any unusual errors.

## After the move

This section of the guide explains the actions that can be performed after completing your move.

> [!NOTE]
> Import of existing security alerts from ATA to [!INCLUDE [Product short](includes/product-short.md)] are not supported. Make sure to record or remediate all existing ATA alerts before decommissioning the ATA Center.

- **Decommission the ATA Center**  
  - To reference the ATA Center data after the move, we recommend keeping the center data online for a period of time. After decommissioning the ATA Center, the number of resources can typically be reduced, especially if the resources are a Virtual Machine.

- **Back up Mongo DB**  
  - If you wish to keep the ATA data indefinitely, [back up Mongo DB](/advanced-threat-analytics/ata-database-management#backing-up-the-ata-database).

## Mission accomplished

Congratulations! Your move from ATA to [!INCLUDE [Product short](includes/product-short.md)] is complete.

## Next steps

Learn more about [[!INCLUDE [Product short](includes/product-short.md)]](what-is.md) features, functionality, and [security alerts](understanding-security-alerts.md).

## Join the Community

Do you have more questions, or an interest in discussing [!INCLUDE [Product short](includes/product-short.md)] and related security with others? Join the [[!INCLUDE [Product short](includes/product-short.md)] Community](<https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection>) today!
