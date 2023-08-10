---
title: Migrate from Advanced Threat Analytics | Microsoft Defender for Identity
description: Learn how to move an existing Advanced Threat Analytics installation to Microsoft Defender for Identity.
ms.date: 08/10/2023
ms.topic: how-to
---

# Advanced Threat Analytics (ATA) to Microsoft Defender for Identity

> [!NOTE]
> The final release of ATA is [generally available](https://support.microsoft.com/help/4568997/update-3-for-microsoft-advanced-threat-analytics-1-9). ATA ended Mainstream Support on January 12, 2021. Extended Support will continue until January 2026. For more information, read [our blog](https://techcommunity.microsoft.com/t5/microsoft-security-and/end-of-mainstream-support-for-advanced-threat-analytics-january/ba-p/1539181).

This article describes how to migrate from an existing ATA installation to Microsoft Defender for Identity:

> [!div class="checklist"]
>
> - Review and confirm Defender for Identity service prerequisites
> - Document your existing ATA configuration
> - Plan your migration
> - Set up and configure your Defender for Identity service
> - Perform post-migration checks and verifications
> - Decommission ATA

> [!NOTE]
> While you can migrate to Defender for Identity from any ATA version, your ATA data isn't migrated. Therefore, we recommend that you plan to retain your ATA Data Center and any alerts required for ongoing investigations until all ATA alerts are closed or remediated.

> [!IMPORTANT]
> This migration guide is designed for Defender for Identity sensors only. <!--what does this even mean?-->
>

## Prerequisites

To migrate from ATA to Defender for Identity, you must have:

- An Azure Active Directory tenant with at least one global/security administrator, so that you can create a Defender for Identity instance. Each Defender for Identity instance supports a multiple Active Directory forest boundary and Forest Functional Level (FFL) of Windows 2003 and above.

- .Net Framework version 4.7 or later. You may also need to restart your domain controller if your current .Net Framework version is not 4.7 or later.

- An environment and domain controllers that meet Defender for Identity sensor requirements. For more information, see [Microsoft Defender for Identity prerequisites](prerequisites.md).

- Verification that all domain controllers you plan to use have sufficient internet access to the Defender for Identity service. For more information, see [Defender for Identity proxy configuration requirements](configure-proxy.md).


## Plan your migration

Before starting the migration, gather all of the following information:

- Account details for your [Directory Services](directory-service-accounts.md) account.

- Syslog notification [settings](/defender-for-identity/notifications).

- Email [notification details](../notifications.md).

- All [ATA role group memberships](/advanced-threat-analytics/ata-role-groups)

- [VPN integration details](../vpn-integration.md)

- Alert exclusions. Exclusions are not transferable from ATA to Defender for Identity, so details of each exclusion are required to [replicate the exclusions in Defender for Identity](../exclusions).

- Account details for entity tags. If you don't already have dedicated entity tags, create new ones for use with Defender for Identity. For more information, see [Defender for Identity identity tags in Microsoft 365 Defender](/microsoft-365/security/defender-identity/entity-tags?view=o365-worldwide&branch=main). <!--is this correct?-->

- A complete list of all entities, such as computers, groups, or users, that you want to manually tag as Sensitive entities. For more information, see [Defender for Identity entity tags in Microsoft 365 Defender](../entity-tags.md).

- Report scheduling [details](/defender-for-identity/classic-reports), including a list of all reports and scheduled timing.

> [!CAUTION]
> Do not uninstall the ATA Center until all ATA Gateways are removed. Uninstalling the ATA Center with ATA Gateways still running leaves your organization exposed with no threat protection.

## Move to Defender for Identity

Use the following steps to migrate to Defender for Identity:

1. [Create your new Defender for Identity instance](deploy-defender-identity.md#start-using-microsoft-365-defender).

1. Uninstall the ATA Lightweight Gateway on all domain controllers.

1. Install the Defender for Identity Sensor on all domain controllers:

    1. [Download the Defender for Identity sensor files](download-sensor.md) and retrieve the access key.
    1. [Install Defender for Identity sensors on your domain controllers](install-sensor.md).

1. [Configure the your Defender for Identity sensor](configure-sensor-settings.md).

After the migration is complete, allow two hours for the initial sync to be completed before moving on with validation tasks.

## Validate your migration

In Microsoft 365 Defender, check the following areas to validate your migration:

- Review any [health issues](/defender-for-identity/health-alerts) for signs of service issues.
- Review Defender for Identity [sensor error logs](troubleshooting-using-logs.md) for any unusual errors.

## Post-migration activities

After completing your migration to Defender for Identity, do the following to clean up your legacy ATA resources:

1. Make sure that you've recorded or remediated all existing ATA alerts. Existing ATA security alerts aren't imported to Defender for Identity with the migration.
1. Do one or both of the following:

    - **Decommission the ATA Center**. We recommend keeping ATA data online for a period of time. 
    - **Back up Mongo DB** if you want to keep the ATA data indefinitely. For more information, see [Backing up the ATA database](/advanced-threat-analytics/ata-database-management#backing-up-the-ata-database).

## Next steps

For more information, see:

- [What is Microsoft Defender for Identity?](../what-is.md)
- [Understanding security alerts](../understanding-security-alerts.md)
- [What's new in Microsoft Defender for Identity](../whats-new.md)
- [Defender for Identity frequently asked questions](../technical-faq.yml).

Do you have more questions, or an interest in discussing Defender for Identity and related security with others? Join the [Defender for Identity Community](<https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection>) today!
