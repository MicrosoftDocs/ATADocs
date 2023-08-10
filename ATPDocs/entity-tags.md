---
title: Entity tags in Microsoft 365 Defender 
description: Learn how to apply Microsoft Defender for Identity entity tags in Microsoft 365 Defender 
ms.date: 01/30/2023
ms.topic: how-to
---

# Defender for Identity entity tags in Microsoft 365 Defender

> [!NOTE]
> The experience described in this page can be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender.

This article explains how to apply entity tags to sensitive accounts. This is important because some Defender for Identity detections, such as sensitive group modification detection and lateral movement path rely on an entity's sensitivity status.

Defender for Identity also enables the configuration of honeytoken accounts, which are used as traps for malicious actors - any authentication associated with these honeytoken accounts (normally dormant), triggers an alert.

## Entity tags

In Microsoft 365 Defender, you can set three types of Defender for Identity entity tags: **Sensitive tags**, **Honeytoken tags**, and **Exchange server tags**.

To set these tags, in [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings** and then **Identities**.

![Go to Settings, then Identities.](media/settings-identities.png)

The tag settings will appear under **Entity tags**.

![Tag setting types.](media/tag-settings.png)

To set each type of tag, follow the instructions below.

## Sensitive  tags

The **Sensitive tag** is used to identify high value assets. The lateral movement path also relies on an entity's sensitivity status. Some entities are considered sensitive automatically by Defender for Identity, and others can be added manually.

### Sensitive entities

The groups in the following list are considered **Sensitive** by Defender for Identity. Any entity that is a member of one of these Active Directory groups (including nested groups and their members) is automatically considered sensitive:

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
  > Until September 2018, Remote Desktop Users were also automatically considered sensitive by Defender for Identity. Remote Desktop entities or groups added after this date are no longer automatically marked as sensitive while Remote Desktop entities or groups added before this date may remain marked as Sensitive. This Sensitive setting can now be changed manually.

In addition to these groups, Defender for Identity identifies the following high value asset servers and automatically tags them as **Sensitive**:

- Certificate Authority Server
- DHCP Server
- DNS Server
- Microsoft Exchange Server

### Manually tag as sensitive

You can also manually tag users, devices, or groups as sensitive.

1. Select **Sensitive**. You'll then see the existing sensitive **Users**, **Devices**, and **Groups**.

    ![Sensitive entities.](media/sensitive-entities.png)

1. Under each category, select **Tag...** to tag that type of entity. For example, under **Groups**, select **Tag groups.** A pane will open with the groups you can select to tag. To search for a group, enter its name in the search box.

    ![Add groups.](media/add-groups.png)

1. Select your group, and select **Add selection.**

    ![Add selection.](media/add-selection.png)

## Honeytoken tags

Honeytoken entities are used as traps for malicious actors. Any authentication associated with these honeytoken entities triggers an alert.

You can tag users or devices with the **Honeytoken** tag in the same way you tag sensitive accounts.

1. Select **Honeytoken**. You'll then see the existing honeytoken **Users** and **Devices**.

    ![Honeytoken entities.](media/honeytoken-entities.png)

1. Under each category, select **Tag...** to tag that type of entity. For example, under **Users**, select **Tag users.** A pane will open with the groups you can select to tag. To search for a group, enter its name in the search box.

    ![Add users.](media/add-users.png)

1. Select your user, and select **Add selection.**

    ![Add selected user.](media/add-selected-user.png)

## Exchange server tags

Defender for Identity considers Exchange servers as high-value assets and automatically tags them as **Sensitive**. You can also manually tag devices as Exchange servers.

1. Select **Exchange server**. You'll then see the existing devices labeled with the **Exchange server** tag.

    ![Exchange servers.](media/exchange-servers.png)

1. To tag a device as an Exchange server, select **Tag devices**.  A pane will open with the devices that you can select to tag. To search for a device, enter its name in the search box.

    ![Add devices.](media/add-devices.png)

1. Select your device, and select **Add selection.**

    ![Select device.](media/select-device.png)

## Next steps

- [Working with suspicious activities](/defender-for-identity/manage-security-alerts)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
