---
title: Advanced settings in Microsoft 365 Defender
description: Learn how to set Microsoft Defender for Identity advanced settings in Microsoft 365 Defender.
ms.date: 09/21/2023
ms.topic: how-to
#CustomerIntent: As a Microsoft Defender for Identity customer, I want to know how and when to use an alert learning mode to reduce the number of false positives.
---

# Advanced settings

This article explains how to work with Microsoft Defender for Identity advanced settings in Microsoft 365 Defender.

## Prerequisites

To access the **Advanced settings** page in Microsoft 365 Defender, you need access at least as a Security administrator.

## Define alert learning period settings

Some Defender for Identity alerts rely on *learning periods* to build a profile of patterns and then distinguish between legitimate and suspicious activities. During a learning period, Defender for Identity learns about your network and builds a profile of your network's normal activity.

By default, new Defender for Identity workspaces have a learning period turned on for the first 30 days so that Defender for Identity can build your network activity profile and send alerts for suspicious activities.

Learning periods, especially in new workspaces, can result in an immediate increase of the number of alerts, with some of them being legitimate traffic and activities.

In the Microsoft 365 Defender **Settings** area, set the **Remove learning period** setting to **Off** to end the learning period manually. For example, you might want to turn the learning period off manually in the following scenarios:

- You're evaluating the service and want to start working immediately
- You've installed a new sensor on a domain controller and don't need a new learning period
- You have a new workspace but feel that Defender for Identity has learned your network sufficiently before the first 30 days is up

For new workspaces, if you haven't turned off the learning period manually by the end of 30 days, Defender for Identity automatically turns the **Remove learning period** setting off and a [health alert](health-alerts.md#learning-mode-has-automatically-ended-for-this-tenant) is triggered to notify administrators.

>[!NOTE]
> Turning off the learning feature for workspaces that have already completed their learning period won't delete the learned profiles, but will simply ignore them.

**To define learning period settings**:

1. In [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings** > **Identities** > **Advanced settings**. 
1. Use the toggle to turn the **Remove learning period** setting on or off.
1. If the **Remove learning period** setting is *On*, modify the sensitivity for each type of alert to determine how sensitive the learning period is. 

    *Normal* means that the learning period is turned off for the selected type of alert. For more information, see [Supported alert types for learning periods](#supported-alert-types-for-learning-periods).

For example:

:::image type="content" source="media/advanced-settings/learning-period.png" alt-text="Screenshot of a learning period turned on." lightbox="media/advanced-settings/learning-period.png":::

Each alert triggered during the learning period is tagged as *POC* to identify it as a learning mode alert.

> [!CAUTION]
> We recommend changing alert sensitivity only after careful consideration. For example, if you have NAT or VPN, we recommend that you do not set relevant detections to high, including *Suspected DCSync attack (replication of directory services)* and  *Suspected identity theft* detections.
>

## Supported alert types for learning periods

The following table lists the alert types that support learning periods and describes the effects of *Medium* and *High* sensitivities.  We recommend changing alert sensitivity only after careful consideration.

|Detection  |Medium  |High  |
|---------|---------|---------|
|**[Account enumeration reconnaissance](reconnaissance-discovery-alerts.md#account-enumeration-reconnaissance-external-id-2003)**     |    On *Medium* mode, this detection triggers immediately and disables the filtering of popular queries in the environment.         |   *High* mode includes everything in *Medium* mode, plus a lower threshold for queries, single scope enumeration, and more.     |
|**[Suspicious additions to sensitive groups](persistence-privilege-escalation-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024)**     |      *Medium* mode not supported for this detection.     |    On *High* mode, this detection avoids the sliding window and ignores any previous learnings.    |
|**[Suspected AD FS DKM key read](credential-access-alerts.md#suspected-ad-fs-dkm-key-read-external-id-2413)**     |    *Medium* mode not supported for this detection.        |   On *High* mode, this detection triggers immediately.      |
|**[Suspected Brute Force attack (Kerberos, NTLM)](credential-access-alerts.md#suspected-brute-force-attack-kerberos-ntlm-external-id-2023)**     |   On *Medium* mode, this detection ignores any learning done and has a lower threshold for failed passwords.           | On *High* mode, this detection ignores any learning done and has the lowest possible threshold for failed passwords.        |
|**[Suspected DCSync attack (replication of directory services)](credential-access-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006)**     |   On *Medium* mode, this detection triggers immediately.         | On *High* mode, this detection triggers immediately and avoids IP filtering like NAT or VPN.        |
|**[Suspected Golden Ticket usage (forged authorization data)](credential-access-alerts.md#suspected-golden-ticket-usage-forged-authorization-data-external-id-2013)**     |       *Medium* mode not supported for this detection.      |     On *High* mode, this detection triggers immediately.    |
|**[Suspected Golden Ticket usage (encryption downgrade)](persistence-privilege-escalation-alerts.md#suspected-golden-ticket-usage-encryption-downgrade-external-id-2009)**     |  *Medium* mode not supported for this detection.           |    On *High* mode, this detection triggers an alert based on lower confidence resolution of a device.     |
|**Suspected identity theft (pass-the-certificate)**     |     On *Medium* mode, this detection triggers immediately.         |  On *High* mode, this detection triggers immediately and avoids IP filtering like NAT or VPN.       |
|**[Suspected identity theft (pass-the-ticket)](lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018)**     |  On *Medium* mode, this detection triggers immediately.           |    On *High* mode, this detection triggers immediately and avoids IP filtering like NAT or VPN.      |
|**[User and Group membership reconnaissance (SAMR)](reconnaissance-discovery-alerts.md#user-and-group-membership-reconnaissance-samr-external-id-2021)**     |     On *Medium* mode, this detection triggers immediately.        |   On *High* mode, this detection triggers immediately and includes a lower alert threshold.  |

For more information, see [Security alerts in Microsoft Defender for Identity](alerts-overview.md).

## Next step

For more information, see [Investigate Defender for Identity security alerts in Microsoft 365 Defender](manage-security-alerts.md).
 