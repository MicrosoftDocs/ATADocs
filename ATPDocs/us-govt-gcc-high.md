---
title: Microsoft Defender for Identity for US Government offerings
description: This article provides an overview of Microsoft Defender for Identity's US Government offerings.
ms.date: 10/13/2021
ms.topic: overview
---

# Microsoft Defender for Identity for US Government offerings

The [!INCLUDE [Product long](includes/product-long.md)] GCC High offering utilizes the same underlying technologies and capabilities as the commercial instance of [!INCLUDE [Product short](includes/product-short.md)]. A list of feature variances can be found in the [Service Description](/enterprise-mobility-security/solutions/ems-azure-atp-govt-service-description).

## Get started with US Government offerings

The [!INCLUDE [Product short](includes/product-short.md)] GCC, GCC High, and Department of Defense (DoD) offerings are built on the Microsoft Azure Government Cloud and is designed to inter-operate with Microsoft 365 GCC, GCC High, and DoD. Use [!INCLUDE [Product short](includes/product-short.md)] public documentation as a [starting point](install-step1.md) for deploying and operating the service and refer to the [Service Description](/enterprise-mobility-security/solutions/ems-mdi-govt-service-description), which details all changes from functionality or features specific to the GCC, GCC High, and DoD environments.

To access Microsoft Defender for Identity for US Government offerings, use the appropriate addresses in this table:

|US Government offering  |Portal  |Workspace |Agent endpoint  |
|---------|---------|---------|---------|
|DoD    |   `portal.azure.atp.us`      |    `<workspacename>.atp.azure.us`     |  `sensorapi.atp.azure.us`       |
|GCC-H   |  `portal.azure.atp.us`       |     `<workspacename>.atp.azure.us`    |  `sensorapi.atp.azure.us`       |
|GCC     |     `portal.gcc.atp.azure.com`    |    `<workspacename>.gcc.atp.azure.com`     |     `sensorapi.gcc.atp.azure.com`    |

You can also use the IP address ranges in our Azure service tag (**AzureAdvancedThreatProtection**) to enable access to Defender for Identity. For more information about service tags, see [Virtual network service tags](/azure/virtual-network/service-tags-overview) or download [the Azure IP Ranges and Service Tags – US Government Cloud file](https://www.microsoft.com/download/details.aspx?id=57063).

## Next steps

- [Learn more about Government offerings](/enterprise-mobility-security/solutions/ems-azure-atp-govt-service-description)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
