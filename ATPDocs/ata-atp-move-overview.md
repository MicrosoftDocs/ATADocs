---
# required metadata

title: Advanced Threat Analytics to Azure Advanced Threat Protection move  | Microsoft Docs
description: Learn how to move an existing Advanced Threat Analytics installation to Azure ATP.
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 10/16/2019
ms.topic: conceptual
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

To learn more about the differences between ATA and Azure ATP, see the [Azure ATP frequently asked questions] (https://docs.microsoft.com/en-us/azure-advanced-threat-protection/atp-technical-faq#what-is-azure-atp).

In this guide you will: 

> [!div class="checklist"]
> * Review and confirm Azure ATP service prerequisites
> * Document your existing ATA configuration
> * Plan your move
> * Set up and configure your Azure ATP  service
> * Perform post move checks and verification
> * Decommission ATA after completing the move 

>[!NOTE]
> Moving to Azure ATP from ATA is possible from any ATA version. However, as data cannot be moved from ATA to Azure ATP, it is recommended to retain your ATA Center data and alerts required for ongoing investigations until all ATA alerts are closed or remediated. 

## Prerequisites

- An Azure Active Directory tenant with at least one global/security administrator is required to create an Azure ATP instance. Each Azure ATP instance supports a multiple Active Directory forest boundary and Forest Functional Level (FFL) of Windows 2003 and above.

- Azure ATP requires .Net Framework 4.7 and may require a domain controller (restart) if your current .Net Framework version is not 4.7.

- Make sure your domain controllers meet all the [Azure ATP sensor requirements](https://docs.microsoft.com/azure-advanced-threat-protection/atp-prerequisites#azure-atp-sensor-requirements) and your environment meets all [Azure ATP requirements](https://docs.microsoft.com/azure-advanced-threat-protection/atp-prerequisites).

- Validate that all domain controllers you plan to use have sufficient internet access to the Azure ATP service. Check and confirm your domain controllers meet the [Azure ATP proxy configuration requirements](https://docs.microsoft.com/azure-advanced-threat-protection/configure-proxy).

>[!NOTE]
> This migration guide is designed for Azure ATP sensors only. For more information, see [choosing the right sensor for your deployment](https://docs.microsoft.com/azure-advanced-threat-protection/atp-capacity-planning#choosing-the-right-sensor-type-for-your-deployment). 

## Plan 

Make sure to gather the following information before starting your move: 
1. Account details for your [Directory Services](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step2) account.
1. Syslog notification [settings](https://docs.microsoft.com/azure-advanced-threat-protection/setting-syslog).
1. Email [notification details](https://docs.microsoft.com/azure-advanced-threat-protection/notifications).
1. ATA roles group membership
1. VPN integration
1. Alert exclusions 
    - Exclusions are not transferable from ATA to Azure ATP, so details of each exclusion are required to [replicate the exclusions in Azure ATP](https://docs.microsoft.com/azure-advanced-threat-protection/excluding-entities-from-detections).
1. Account details for HoneyToken accounts. 
    - If you don't already have dedicated HoneyToken accounts, learn more about [HoneyTokens in Azure ATP](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step7) and create new accounts to use for this purpose.
1. Complete list of all entities (computers, groups, users) you wish to manually tag as Sensitive entities. 
    - Learn more about the importance of [Sensitive entities](https://docs.microsoft.com/azure-advanced-threat-protection/sensitive-accounts) in Azure ATP.
1. Report scheduling [details](https://docs.microsoft.com/azure-advanced-threat-protection/reports) (list of reports and scheduled timing). 
1. Identification and details of each ATA Lightweight Gateway that is an Azure ATP Domain Synchronizer candidate. 
   - Learn more about the importance of [Domain Synchronizer candidates](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step5#configure-sensor-settings) in Azure ATP.

> [!NOTE]
> Do not uninstall the ATA Center until all ATA Gateways are removed. Uninstalling the ATA Center with ATA Gateways still running leaves your organization exposed with no threat protection.

## Move 

Complete your move to Azure ATP in two easy steps:

### Step 1: Create and install Azure ATP instance and sensors

1. [Create your new Azure ATP instance](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step1)

2. Uninstall the ATA Lightweight Gateway on all domain controllers.  

3. Install the Azure ATP Sensor on all domain controllers:
     - [Download the Azure ATP sensor files](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step3).
     - [Retrieve your Azure ATP Access Key](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step3#download-the-setup-package).
     - [Install Azure ATP sensors on your domain controllers](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step4). 

### Step 2: Configure and validate Azure ATP instance  

- [Configure the Sensor](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step5)

>[!NOTE]
> Certain tasks in the following list cannot be completed before installing Azure ATP sensors and then completing an initial sync, such as selecting entities for manual **Sensitive** tagging. Allow up to 2 hours for the initial sync to be completed. 

#### Configuration

Sign in to the Azure ATP portal and complete the following configuration tasks.

| Step    | Action | Status |
|--------------|------------|------------------|
| 1  | Set [delayed updates on a selection of domain controllers](https://docs.microsoft.com/azure-advanced-threat-protection/sensor-update) | - [ ] |
| 2  | [Directory Services](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step2) account details| - [ ] |
| 3  | Configure [Domain Synchronizer candidates](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step5#configure-sensor-settings) | - [ ] |
| 4  | Configure [Syslog notifications](https://docs.microsoft.com/azure-advanced-threat-protection/setting-syslog) | - [ ] |
| 5  | [Integrate VPN](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step6-vpn) information| - [ ] |
| 6  | Configure [WDATP integration](https://docs.microsoft.com/azure-advanced-threat-protection/integrate-wd-atp)| - [ ] |
| 7  | Set [HoneyTokens](https://docs.microsoft.com/azure-advanced-threat-protection/install-atp-step7) accounts| - [ ] |
| 8  | Tag [Sensitive entities](https://docs.microsoft.com/azure-advanced-threat-protection/sensitive-accounts)| - [ ] |
| 9  | Create [Security alert exclusions](https://docs.microsoft.com/azure-advanced-threat-protection/excluding-entities-from-detections)| - [ ] |
| 10 | [Email notification toggles](https://docs.microsoft.com/azure-advanced-threat-protection/notifications) | - [ ] |
| 11  | [Schedule report settings](https://docs.microsoft.com/azure-advanced-threat-protection/reports) (list of reports and scheduled timing)| - [ ] |
| 12  | Configure [Role based permissions](https://docs.microsoft.com/azure-advanced-threat-protection/atp-role-groups) | - [ ] |
| 12  | [SIEM notification configuration (IP address)](https://docs.microsoft.com/azure-advanced-threat-protection/configure-event-collection#siemsyslog)| - [ ] | 

#### Validation

Within the Azure ATP portal:
- Review any [health alerts](https://docs.microsoft.com/azure-advanced-threat-protection/atp-health-center) for signs of service issues. 
- Review Azure ATP [Sensor error logs](https://docs.microsoft.com/azure-advanced-threat-protection/troubleshooting-atp-using-logs) for any unusual errors.

## After the move

This section of the guide explains the actions that can be performed after completing your move. 

>[!NOTE]
> Import of existing security alerts from ATA to ATP are not supported. Make sure to record or remediate all existing ATA alerts before decommissioning the ATA Center.  

- **Decommission the ATA Center** 
    - To reference the ATA Center data after the move, we recommend keeping the center data online for a period of time. After decommissioning the ATA Center, the number of resources can typically be reduced, especially if the resources are a Virtual Machine.  

- **Back up Mongo DB** 
    - If you wish to keep the ATA data indefinitely, [back up Mongo DB](https://docs.microsoft.com/advanced-threat-analytics/ata-database-management#backing-up-the-ata-database).  

## Mission accomplished

Congratulations! Your move from ATA to Azure ATP is complete. 

## Next steps

Learn more about [Azure ATP](https://docs.microsoft.com/azure-advanced-threat-protection/what-is-atp) features, functionality, and [security alerts](https://docs.microsoft.com/azure-advanced-threat-protection/understanding-security-alerts).  
## Join the Community

Do you have more questions, or an interest in discussing Azure ATP and related security with others? Join the [Azure ATP Community](https://techcommunity.microsoft.com/t5/Azure-Advanced-Threat-Protection/bd-p/AzureAdvancedThreatProtection) today!




