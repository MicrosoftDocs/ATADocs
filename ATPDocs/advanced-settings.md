---
title: Advanced settings in Microsoft 365 Defender
description: Learn how to set Microsoft Defender for Identity advanced settings in Microsoft 365 Defender.
ms.date: 01/29/2023
ms.topic: how-to
---

# Advanced settings

This article explains how to work with Microsoft Defender for Identity advanced settings in Microsoft 365 Defender.

## Learning period for alerts

Microsoft Defender for Identity security alerts explain the suspicious activities detected by Defender for Identity sensors on your network, and the actors and computers involved in each threat.

Some of the Defender for Identity alerts heavily use profiling, deterministic detection, machine learning, and behavioral algorithms which Defender for Identity learned about your network. Full learning can take up to 30 days per domain controller.

To learn more about which alerts have learning periods, see [Microsoft Defender for Identity Security Alerts](alerts-overview.md).

>[!NOTE]
>In some cases, you may want to get notified on alerts, even when the profiling was not completed. For example, when you install a sensor on a new domain controller or when evaluating the product.

## Removing the learning period

> [!NOTE]
> This option is only available for Security Administrators or Global Administrators.

With this feature, you can turn off the learning period for the affected alerts. Every alert that is based on learning or profile, will be triggered instantly.

We highly recommend only enabling it for a short period of time, as turning on this setting might result in a high volume of alerts, with some of the alerts being legitimate activity.

During the time this toggle is enabled, the learning of the environment will continue.

> [!NOTE]
> Turning this feature on for tenants who have completed their learning period **will not delete** the learned profiles, but just ignore them.

## How to remove the learning period

1. In [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings** and then **Identities**.

    ![Go to Settings, then Identities.](media/settings-identities.png)

1. You'll then see **Advanced settings** in the left-hand menu.

    :::image type="content" source="media/advanced-settings-menu.png" alt-text="Advanced settings menu.":::

1. Disable the learning period by toggling the **Remove learning period** button to **On**.

    :::image type="content" source="media/remove-learning-period-toggle.png" alt-text="Toggle remove learning period button.":::

    > [!NOTE]
    > When the toggle is on and the learning is disabled, this message will appear in the Defender for Identity settings:
    >
    > "The learning period for alerts is disabled. This might increase the number of alerts for some legitimate alerts and activities."

## See also

- [Defender for Identity security alerts in Microsoft 365 Defender](manage-security-alerts.md)
- [Check out the Defender for Identity forum!](<https://aka.ms/MDIcommunity>)
