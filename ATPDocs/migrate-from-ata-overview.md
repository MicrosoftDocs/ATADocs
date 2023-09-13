---
title: Move from Advanced Threat Analytics 
description: Learn how to move an existing Advanced Threat Analytics installation to Microsoft Defender for Identity.
ms.date: 02/15/2023
ms.topic: how-to
---

# Advanced Threat Analytics (ATA) to Microsoft Defender for Identity

> [!NOTE]
> The final release of ATA is [generally available](https://support.microsoft.com/help/4568997/update-3-for-microsoft-advanced-threat-analytics-1-9). ATA ended Mainstream Support on January 12, 2021. Extended Support will continue until January 2026. For more information, read [our blog](https://techcommunity.microsoft.com/t5/microsoft-security-and/end-of-mainstream-support-for-advanced-threat-analytics-january/ba-p/1539181).

Use this guide to move from an existing ATA installation to the (Microsoft Defender for Identity) service. The guide explains Defender for Identity prerequisites and requirements, and details how to plan and then complete your move. Validation steps and tips to take advantage of the latest threat protection and security solutions with Defender for Identity after installation are also included.

To learn more about the differences between ATA and Defender for Identity, see the [Defender for Identity frequently asked questions](technical-faq.yml).

In this guide you will:

> [!div class="checklist"]
>
> - Review and confirm Defender for Identity service prerequisites
> - Document your existing ATA configuration
> - Plan your move
> - Set up and configure your Defender for Identity  service
> - Perform post move checks and verification
> - Decommission ATA after completing the move

> [!NOTE]
> Moving to Defender for Identity from ATA is possible from any ATA version. However, as data cannot be moved from ATA to Defender for Identity, it is recommended to retain your ATA Center data and alerts required for ongoing investigations until all ATA alerts are closed or remediated.

## Prerequisites

- An Azure Active Directory tenant with at least one global/security administrator is required to create a Defender for Identity instance. Each Defender for Identity workspace supports a multiple Active Directory forest boundary and Forest Functional Level (FFL) of Windows 2003 and above.

- Defender for Identity requires .Net Framework 4.7 or later and may require a domain controller restart if your current .Net Framework version is not 4.7 or later.

- Make sure your domain controllers meet all the [Defender for Identity sensor requirements](prerequisites.md#defender-for-identity-sensor-requirements) and your environment meets all [Defender for Identity requirements](prerequisites.md).

- Validate that all domain controllers you plan to use have sufficient internet access to the Defender for Identity service. Check and confirm your domain controllers meet the [Defender for Identity proxy configuration requirements](configure-proxy.md).

> [!NOTE]
> This migration guide is designed for Defender for Identity sensors only.

## Plan

Make sure to gather the following information before starting your move:

1. Account details for your [Directory Services](directory-service-accounts.md) account.
1. Syslog notification [settings](/defender-for-identity/notifications).
1. Email [notification details](notifications.md).
1. ATA roles group membership
1. VPN integration
1. Alert exclusions
    - Exclusions are not transferable from ATA to Defender for Identity, so details of each exclusion are required to [replicate the exclusions in Defender for Identity](/defender-for-identity/exclusions).
1. Account details for honeytoken accounts.
    - If you don't already have dedicated honeytoken accounts, learn more about [honeytokens in Defender for Identity](/defender-for-identity/classic-manage-sensitive-honeytoken-accounts) and create new accounts to use for this purpose.
1. Complete list of all entities (computers, groups, users) you wish to manually tag as Sensitive entities.
    - Learn more about the importance of [Sensitive entities](/defender-for-identity/entity-tags) in Defender for Identity.
1. Report scheduling [details](/defender-for-identity/classic-reports) (list of reports and scheduled timing).

> [!NOTE]
> Do not uninstall the ATA Center until all ATA Gateways are removed. Uninstalling the ATA Center with ATA Gateways still running leaves your organization exposed with no threat protection.

## Move

Complete your move to Defender for Identity in two easy steps:

### Step 1: Create and install Defender for Identity workspace and sensors

1. [Create your new Defender for Identity instance](deploy-defender-identity.md#start-using-microsoft-365-defender)

1. Uninstall the ATA Lightweight Gateway on all domain controllers.

1. Install the Defender for Identity Sensor on all domain controllers:
    - [Download the Defender for Identity sensor files](download-sensor.md) and retrieve the access key.
    - [Install Defender for Identity sensors on your domain controllers](install-sensor.md).

### Step 2: Configure and validate Defender for Identity instance

- [Configure the Sensor](configure-sensor-settings.md)

> [!NOTE]
> Certain tasks in the following list cannot be completed before installing Defender for Identity sensors and then completing an initial sync, such as selecting entities for manual **Sensitive** tagging. Allow up to 2 hours for the initial sync to be completed.

#### Validation

In the Microsoft 365 Defender portal:

- Review any [health issues](/defender-for-identity/health-alerts) for signs of service issues.
- Review Defender for Identity [Sensor error logs](troubleshooting-using-logs.md) for any unusual errors.

## After the move

This section of the guide explains the actions that can be performed after completing your move.

> [!NOTE]
> Import of existing security alerts from ATA to Defender for Identity are not supported. Make sure to record or remediate all existing ATA alerts before decommissioning the ATA Center.

- **Decommission the ATA Center**  
  - To reference the ATA Center data after the move, we recommend keeping the center data online for a period of time. After decommissioning the ATA Center, the number of resources can typically be reduced, especially if the resources are a Virtual Machine.

- **Back up Mongo DB**  
  - If you wish to keep the ATA data indefinitely, [back up Mongo DB](/advanced-threat-analytics/ata-database-management#backing-up-the-ata-database).

## Mission accomplished

Congratulations! Your move from ATA to Defender for Identity is complete.

## Next steps

Learn more about [Defender for Identity](what-is.md) features, functionality, and [security alerts](understanding-security-alerts.md).

## Join the Community

Do you have more questions, or an interest in discussing Defender for Identity and related security with others? Join the [Defender for Identity Community](<https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection>) today!
