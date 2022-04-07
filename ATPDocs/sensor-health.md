---
title: Monitoring domain controllers and installed sensors installed on your domain controllers using Microsoft Defender for Identity
description: Describes how to monitor Microsoft Defender for Identity sensors and sensor coverage using Defender for Identity
ms.date: 04/07/2022
ms.topic: how-to
---

# Monitoring your domain controller coverage

As soon as the first [!INCLUDE [Product long](includes/product-long.md)] sensor is installed and configured on any domain controller in your network, [!INCLUDE [Product short](includes/product-short.md)] begins monitoring your environment for domain controllers.

Once a [!INCLUDE [Product short](includes/product-short.md)] sensor is installed and configured on a domain controller in your network, the sensor communicates with the [!INCLUDE [Product short](includes/product-short.md)] service on a constant basis sending sensor status, health and version information, and collected Active Directory events and changes.

## Domain controller status

[!INCLUDE [Product short](includes/product-short.md)] continuously monitors your environment for unmonitored domain controllers introduced into your environment, and reports on them to assist you in managing full coverage of your environment.

1. To check the status of your detected monitored and unmonitored domain controllers and their status, go to the **Configuration** area of the [!INCLUDE [Product short](includes/product-short.md)] portal and, under the **System** section, select **Sensors**.

    ![[!INCLUDE [Product short.](includes/product-short.md)] sensor status monitoring](media/sensors-status-monitoring.png)

1. Your currently monitored and unmonitored domain controllers are displayed at the top of the screen. To download the monitoring status details of your domain controllers, select **Download Details**.

The domain controller coverage Excel download provides the following information for all detected domain controllers in your organization:

|Title|Description|
|----|----|
|Hostname|Computer name|
|Domain name|Domain name|
|Monitored|[!INCLUDE [Product short](includes/product-short.md)] monitoring status|
|Sensor type|[!INCLUDE [Product short](includes/product-short.md)] sensor or [!INCLUDE [Product short](includes/product-short.md)] standalone sensor|
|Organizational unit|Location inside of Active Directory |
|Operating system version| Version of operating system detected|
|IP address|Detected IP address|

## Search domain controllers

Managing your fleet of sensors and domain controllers can be challenging. To make it easier to find and identify, domain controllers can be searched using the search feature in [!INCLUDE [Product short](includes/product-short.md)] Sensors list.

1. To search your domain controllers, go to the **Configuration** area of the [!INCLUDE [Product short](includes/product-short.md)] portal and, under the **System** section, select **Sensors**.
1. Select the filter option on the **domain controller** column in the domain controller table list.
1. Enter the name you wish to search. Wildcards are not currently supported in the search field.

    ![[!INCLUDE [Product short.](includes/product-short.md)] search domain controller](media/search-sensor.png)

> [!NOTE]
> [!INCLUDE [Product short](includes/product-short.md)] portal configuration pages can be modified by [!INCLUDE [Product short](includes/product-short.md)] admins only.

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] Architecture](architecture.md)
- [Configuring [!INCLUDE [Product short](includes/product-short.md)] sensors](install-step5.md)
- [Multi-forest support](multi-forest.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
