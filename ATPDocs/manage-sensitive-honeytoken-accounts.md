---
title: Manage sensitive or honeytoken accounts with Microsoft Defender for Identity
description: Describes how to manage sensitive or honeytoken accounts using Microsoft Defender for Identity
ms.date: 02/17/2021
ms.topic: how-to
---

# Manage sensitive or honeytoken accounts

> [!NOTE]
> The experience described in this page can also be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender. The supporting documents for the new experience can be found [here](/microsoft-365/security/defender-identity/entity-tags). For more information about Microsoft Defender for Identity and when other features will be available in Microsoft 365 Defender, see [Microsoft Defender for Identity in Microsoft 365 Defender](defender-for-identity-in-microsoft-365-defender.md).

This article explains how to apply entity tags to sensitive accounts. This is important because some [!INCLUDE [Short long](includes/product-short.md)] detections, such as sensitive group modification detection and lateral movement path rely on an entity's sensitivity status.

[!INCLUDE [Product short](includes/product-short.md)] also enables the configuration of honeytoken accounts, which are used as traps for malicious actors - any authentication associated with these honeytoken accounts (normally dormant), triggers an alert.

## Sensitive entities

The following list of groups are considered **Sensitive** by [!INCLUDE [Short long](includes/product-short.md)]. Any entity that is a member of one of these Active Directory groups (including nested groups and their members) is automatically considered sensitive:

- Administrators
- Power Users
- Account Operators
- Server Operators
- Print Operators
- Backup Operators
- Replicators
- Network Configuration Operators
- Incoming Forest Trust Builders
- Domain Admins
- Domain Controllers
- Group Policy Creator Owners
- Read-only Domain Controllers
- Enterprise Read-only Domain Controllers
- Schema Admins
- Enterprise Admins
- Microsoft Exchange Servers

  > [!NOTE]
  > Until September, 2018, Remote Desktop Users were also automatically considered sensitive by [!INCLUDE [Product short](includes/product-short.md)]. Remote Desktop entities or groups added after this date are no longer automatically marked as sensitive while Remote Desktop entities or groups added before this date may remain marked as Sensitive. This Sensitive setting can now be changed manually.

In addition to these groups, [!INCLUDE [Product short](includes/product-short.md)] identifies the following high value asset servers and automatically tags them as **Sensitive**:

- Certificate Authority Server
- DHCP Server
- DNS Server
- Microsoft Exchange Server

## Manually tagging entities

You can also manually tag entities as sensitive or honeytoken accounts. If you manually tag additional users or groups, such as board members, company executives, and sales directors, [!INCLUDE [Product short](includes/product-short.md)] will consider them sensitive.

### To manually tag entities

To tag entities, do the following:

1. In the [!INCLUDE [Product short](includes/product-short.md)] portal, select **Configuration**.

    ![[!INCLUDE [Product short.](includes/product-short.md)] configuration settings](media/config-menu.png)

1. Under **Detection**, select **Entity tags**.

    ![[!INCLUDE [Product short.](includes/product-short.md)] entity tags](media/entity-tags.png)

1. For each account that you want to configure, do the following:
    1. Under **Honeytoken accounts** or **Sensitive**, enter the account name.
    1. Click the plus icon **(+)**.

    > [!TIP]
    > The sensitive or honeytoken account field is searchable and will autofill with entities in your network.

    ![[!INCLUDE [Product short.](includes/product-short.md)] sensitive account sample](media/sensitive-account-sample.png)

1. Click **Save**.

## See also

- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
