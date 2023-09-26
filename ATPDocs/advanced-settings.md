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

By default, new Defender for Identity workspaces have an alert *learning period* turned on for the first 30 days. During the learning period, Defender for Identity learns about your network and builds a profile of your network's normal activity. When 30 days is complete, the learning period is automatically turned off and a health alert is triggered to notify administrators.

Learning periods can be useful for updating your baseline algorithms, but can also result in a high volume of alerts, some of which may be triggered by legitimate activity. If Defender for Identity has learned your network sufficiently, you may want to remove the learning period before the 30 days is up.

For example, when you install a new sensor on a domain controller or when you're evaluating the product, you may want to get alerts immediately. In such cases, you can turn off the learning period for the affected alerts by enabling the **Remove learning period** feature.

>[!NOTE]
> Turning off the learning feature for instances that have already completed their learning period won't delete the learned profiles, but will simply ignore them.

**To define learning period settings**:

1. In [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings** > **Identities** > **Advanced settings**. 
1. Use the toggle to turn the learning period on or off.
1. If the learning period is on, modify the sensitivity for each type of alert to determine how sensitive the learning period is. *Normal* means that learn mode is turned off for the selected type of alert. For more information, see [Supported alert types for learning periods](#supported-alert-types-for-learning-periods).

For example:

:::image type="content" source="media/advanced-settings/learning-period.png" alt-text="Screenshot of a learning period turned on.":::

Each alert triggered during the learning period is tagged as *POC* to identify it as a learning mode alert.

> [!CAUTION]
> We recommend changing alert sensitivity only after careful consideration. For example, if you have NAT or VPN, we recommend that you do not set relevant detections to high, including *Suspected DCSync attack (replication of directory services)* and  *Suspected identity theft* detections.
>

## Supported alert types for learning periods

The following table lists the alert types that support learning periods and describes the effects of *Medium* and *High* sensitivities.  We recommend changing alert sensitivity only after careful consideration.

|Detection  |Medium  |High  |
|---------|---------|---------|
|**Account enumeration reconnaissance**     |    On *Medium* mode, this detection triggers immediately and disables the filtering of popular queries in the environment.         |   *High* mode includes everything in *Medium* mode, plus a lower threshold for queries, single scope enumeration, and more.     |
|**Suspicious additions to sensitive groups**     |      *Medium* mode not supported for this detection.     |    On *High* mode, this detection avoids the sliding window and ignores any previous learnings.    |
|**Suspected AD FS DKM key read**     |    *Medium* mode not supported for this detection.        |   On *High* mode, this detection triggers immediately.      |
|**Suspected Brute Force attack (Kerberos, NTLM)**     |   On *Medium* mode, this detection ignores any learning done and has a lower threshold for failed passwords.           | On *High* mode, this detection ignores any learning done and has the lowest possible threshold for failed passwords.        |
|**Suspected DCSync attack (replication of directory services)**     |   On *Medium* mode, this detection triggers immediately.         | On *High* mode, this detection triggers immediately and avoids IP filtering like NAT or VPN.        |
|**Suspected Golden Ticket usage (forged authorization data)**     |       *Medium* mode not supported for this detection.      |     On *High* mode, this detection triggers immediately.    |
|**Suspected Golden Ticket usage (encryption downgrade)**     |  *Medium* mode not supported for this detection.           |    On *High* mode, this detection triggers an alert based on lower confidence resolution of a device.     |
|**Suspected identity theft (pass-the-certificate)**     |     On *Medium* mode, this detection triggers immediately.         |  On *High* mode, this detection triggers immediately and avoids IP filtering like NAT or VPN.       |
|**Suspected identity theft (pass-the-ticket)**     |  On *Medium* mode, this detection triggers immediately.           |    On *High* mode, this detection triggers immediately and avoids IP filtering like NAT or VPN.      |
|**User and Group membership reconnaissance (SAMR)**     |     On *Medium* mode, this detection triggers immediately.        |   On *High* mode, this detection triggers immediately and includes a lower alert threshold.  |

For more information, see [Security alerts in Microsoft Defender for Identity](alerts-overview.md).

## Next step

For more information, see [Investigate Defender for Identity security alerts in Microsoft 365 Defender](manage-security-alerts.md).
 