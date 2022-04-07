---
title: Uninstall Microsoft Defender for Identity sensor
description: This article describes how to uninstall the Microsoft Defender for Identity sensor from domain controllers.
ms.date: 04/07/2022
ms.topic: how-to
---

# Uninstall the Microsoft Defender for Identity sensor

This article describes how to uninstall the [!INCLUDE [Product long](includes/product-long.md)] sensor from domain controllers for the following scenarios:

1. Uninstall a sensor from a domain controller
1. Remove an orphaned sensor
1. Remove a duplicate sensor

## Uninstall a sensor from a domain controller

The following steps describe how to uninstall a sensor from a domain controller.

1. Sign in to the domain controller with administrative privileges.
1. From the Windows **Start** menu, select **Settings** > **Control Panel** > **Add/ Remove Programs**.
1. Select the sensor installation, select **Uninstall**, and follow the instructions to remove the sensor.

## Remove an orphaned sensor

This scenario can occur when a domain controller was deleted without first uninstalling the sensor, and the sensor still appears in the [!INCLUDE [Product short](includes/product-short.md)] portal.

1. In [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings** and then **Identities**. Select the **Sensors** tab, which displays all your Defender for Identity sensors.
1. Locate the orphaned sensor and select **Delete** (trash can icon).

    ![Delete orphaned [!INCLUDE [Product short.](includes/product-short.md)] sensor from sensors page](media/delete-orphaned-sensor.png)

## Remove a duplicate sensor

This scenario may occur after an in-place sensor upgrade, and the sensor appears twice in the [!INCLUDE [Product short](includes/product-short.md)] portal.

1. In [Microsoft 365 Defender](https://security.microsoft.com), go to **Settings** and then **Identities**. Select the **Sensors** tab, which displays all your Defender for Identity sensors.
1. Locate the orphaned sensor and select **Delete** (trash can icon).

## See also

- [Manage and update Microsoft Defender for Identity sensors](sensor-settings.md)
