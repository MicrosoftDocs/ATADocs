---
title: Tag sensitive accounts with Microsoft Defender for Identity
description: Describes how to tag sensitive accounts using Microsoft Defender for Identity
ms.date: 10/27/2020
ms.topic: how-to
---

# Working with sensitive accounts

## Sensitive entities

The following list of groups are considered **Sensitive** by [!INCLUDE [Product long](includes/product-long.md)]. Any entity that is a member of one of these groups is considered sensitive:

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
- read-only Domain Controllers
- Enterprise Read-only Domain Controllers
- Schema Admins
- Enterprise Admins
- Microsoft Exchange Servers

  > [!NOTE]
  > Until September, 2018, Remote Desktop Users were also automatically considered Sensitive by [!INCLUDE [Product short](includes/product-short.md)]. Remote Desktop entities or groups added after this date are no longer automatically marked as sensitive while Remote Desktop entities or groups added before this date may remain marked as Sensitive. This Sensitive setting can now be changed manually.

In addition to these groups, [!INCLUDE [Product short](includes/product-short.md)] identifies the following high value asset servers and automatically tags them as **Sensitive**:

- Certificate Authority Server
- DHCP Server
- DNS Server
- Microsoft Exchange Server

## Tagging sensitive accounts

In addition to these groups, you can manually tag groups or accounts as sensitive to enhance detections. This is important because Some [!INCLUDE [Product short](includes/product-short.md)] detections, such as sensitive group modification detection and lateral movement paths, rely on which groups and accounts are considered sensitive. You can manually tag other users or groups as sensitive, such as board members, company executives, director of sales, etc., and [!INCLUDE [Product short](includes/product-short.md)] considers them sensitive.

1. In the [!INCLUDE [Product short](includes/product-short.md)] portal, select **Configuration**.

1. Under **Detection** click **Entity tags**.

    ![[!INCLUDE [Product short](includes/product-short.md)] entity tags](media/entity-tags.png)

1. In the **Sensitive** section, type the name of the **Sensitive accounts** and **Sensitive groups** and then click **+** sign to add them.

    ![[!INCLUDE [Product short](includes/product-short.md)] sensitive account sample](media/sensitive-account-sample.png)

1. Click **Save**.

## See also

- [Working with suspicious activities](working-with-suspicious-activities.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](https://aka.ms/MDIcommunity)
