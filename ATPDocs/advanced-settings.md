---
title: Advanced settings in Microsoft 365 Defender
description: Learn how to set Microsoft Defender for Identity advanced settings in Microsoft 365 Defender.
ms.date: 10/22/2023
ms.topic: how-to
#CustomerIntent: As a Microsoft Defender for Identity customer, I want to know how and when to use an alert learning mode to reduce the number of false positives.
---

# Advanced settings

This article explains how to work with Microsoft Defender for Identity advanced settings in Microsoft 365 Defender.

## Prerequisites

To access the **Advanced settings** page in Microsoft 365 Defender, you need access at least as a Security administrator.

## Define alert learning period settings

Some Defender for Identity alerts wait for a *learning period* before alerts are triggered. During this learning period, Defender for Identity builds a profile of patterns to use when distinguishing between legitimate and suspicious activities.

By default, after deploying your first sensor, new Defender for Identity workspaces are configured with a **Remove learning period** set to *On*.

Setting the **Remove learning period** option to *On* causes Defender for Identity to trigger affected alerts even while your baseline is still being built. The default setting for new workspaces is designed to help you start evaluating Defender for Identity as soon and as thoroughly as possible.

However, the **Remove learning period** setting turned *On* can result in an immediate increase of the number of alerts, with some of them being legitimate traffic and activities. You might want to turn the **Remove learning period** setting *Off* manually, before the first 30 days are up, such as if you have a new workspace, but feel that Defender for Identity has learned your network sufficiently before the first 30 days are up.

Any alerts that are affected by the **Remove learning period** setting, and are triggered while the setting is set to *On*, have an extra indication in the **Important information** section of the alert.

If the **Remove learning period** setting is still *On* at the end of 30 days, Defender for Identity automatically turns it *Off* and opens a [health issue](health-alerts.md#the-remove-learning-period-toggle-was-automatically-switched-off-for-this-tenant) to notify administrators.

>[!NOTE]
> Turning *Off* the **Remove learning period** setting for workspaces that have already completed their learning period won't delete the learned profiles, but will ignore them for any alerts with sensitivity level *Medium* or *High*.

**To define learning period settings**:

1. In [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings** > **Identities** > **Advanced settings**. 

1. Use the toggle to turn the **Remove learning period** setting *On* or *Off*.

1. If the **Remove learning period** setting is *On*, modify the sensitivity for each type of alert as needed for your organization.

    *Normal* means that the **Remove learning period** setting is turned *Off* for the selected type of alert. For more information, see [Supported alert types for learning periods](#supported-alert-types-for-learning-periods).

    > [!CAUTION]
    > We recommend changing alert sensitivity only after careful consideration. For example, if you have NAT or VPN, we recommend that you do not set relevant detections to *High*, including *Suspected DCSync attack (replication of directory services)* and  *Suspected identity theft* detections.
    >

For example:

:::image type="content" source="media/advanced-settings/learning-period.png" alt-text="Screenshot of a learning period turned on." lightbox="media/advanced-settings/learning-period.png":::


## Supported alert types for learning periods

The following table lists the alert types that support learning periods and describes the effects of *Medium* and *High* sensitivities.  We recommend changing alert sensitivity only after careful consideration.

*Normal* means that the **Remove learning period** setting is turned *Off* for the selected type of alert. For more information, see [Supported alert types for learning periods](#supported-alert-types-for-learning-periods).


|Detection  |Medium  |High  |
|---------|---------|---------|
|**[Security principal reconnaissance (LDAP)](credential-access-alerts.md#security-principal-reconnaissance-ldap-external-id-2038)**     |    On *Medium* mode, this detection triggers immediately and disables the filtering of popular queries in the environment.         |   *High* mode includes everything in *Medium* mode, plus a lower threshold for queries, single scope enumeration, and more.     |
|**[Suspicious additions to sensitive groups](persistence-privilege-escalation-alerts.md#suspicious-additions-to-sensitive-groups-external-id-2024)**     |      *Medium* mode not supported for this detection.     |    On *High* mode, this detection avoids the sliding window and ignores any previous learnings.    |
|**[Suspected AD FS DKM key read](credential-access-alerts.md#suspected-ad-fs-dkm-key-read-external-id-2413)**     |    *Medium* mode not supported for this detection.        |   On *High* mode, this detection triggers immediately.      |
|**[Suspected Brute Force attack (Kerberos, NTLM)](credential-access-alerts.md#suspected-brute-force-attack-kerberos-ntlm-external-id-2023)**     |   On *Medium* mode, this detection ignores any learning done and has a lower threshold for failed passwords.           | On *High* mode, this detection ignores any learning done and has the lowest possible threshold for failed passwords.        |
|**[Suspected DCSync attack (replication of directory services)](credential-access-alerts.md#suspected-dcsync-attack-replication-of-directory-services-external-id-2006)**     |   On *Medium* mode, this detection triggers immediately.         | On *High* mode, this detection triggers immediately and avoids IP filtering like NAT or VPN.        |
|**[Suspected Golden Ticket usage (forged authorization data)](credential-access-alerts.md#suspected-golden-ticket-usage-forged-authorization-data-external-id-2013)**     |       *Medium* mode not supported for this detection.      |     On *High* mode, this detection triggers immediately.    |
|**[Suspected Golden Ticket usage (encryption downgrade)](persistence-privilege-escalation-alerts.md#suspected-golden-ticket-usage-encryption-downgrade-external-id-2009)**     |  *Medium* mode not supported for this detection.           |    On *High* mode, this detection triggers an alert based on lower confidence resolution of a device.     |
|**[Suspected identity theft (pass-the-ticket)](lateral-movement-alerts.md#suspected-identity-theft-pass-the-ticket-external-id-2018)**     |  On *Medium* mode, this detection triggers immediately.           |    On *High* mode, this detection triggers immediately and avoids IP filtering like NAT or VPN.      |
|**[User and Group membership reconnaissance (SAMR)](reconnaissance-discovery-alerts.md#user-and-group-membership-reconnaissance-samr-external-id-2021)**     |     On *Medium* mode, this detection triggers immediately.        |   On *High* mode, this detection triggers immediately and includes a lower alert threshold.  |

For more information, see [Security alerts in Microsoft Defender for Identity](alerts-overview.md).

## Next step

For more information, see [Investigate Defender for Identity security alerts in Microsoft 365 Defender](manage-security-alerts.md).
 
