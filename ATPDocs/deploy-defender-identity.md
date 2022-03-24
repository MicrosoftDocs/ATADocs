---
title: Deploy Defender for Identity with Microsoft 365 Defender
description: Learn how to deploy Microsoft Defender for Identity using Microsoft 365 Defender
ms.date: 03/24/2022
ms.topic: how-to
---

# Deploy Microsoft Defender for Identity with Microsoft 365 Defender

Learn how to deploy Microsoft Defender for Identity using Microsoft 365 Defender.

> [!IMPORTANT]
> Currently, [!INCLUDE [Product short](includes/product-short.md)] data centers are deployed in Europe, UK, North America/Central America/Caribbean and Asia. Your instance is created automatically in the data center that is geographically closest to your Azure Active Directory (Azure AD). Once created, [!INCLUDE [Product short](includes/product-short.md)] instances aren't movable.

After you've [prepared your environment](prerequisites.md), you can deploy Microsoft Defender for Identity using Microsoft 365 Defender.

## Start using Microsoft 365 Defender

To begin the deployment of Defender for Identity, sign in to the [Microsoft 365 Defender portal](https://security.microsoft.com). From the navigation menu, select any item, such as **Incidents & alerts**, **Hunting**, **Action center**, or **Threat analytics** to initiate the onboarding process.

You'll then be given the option to deploy supported services, including Microsoft Defender for Identity. When you go to the Defender for Identity settings, the required cloud components will be auto-provisioned.

For more information about these steps, see the following articles:

- [Get started with Microsoft 365 Defender](/microsoft-365/security/defender/get-started)
- [Turn on Microsoft 365 Defender](/microsoft-365/security/defender/m365d-enable)
- [Deploy supported services](/microsoft-365/security/defender/deploy-supported-services)
- [Frequently asked questions when turning on Microsoft 365 Defender](/microsoft-365/security/defender/m365d-enable-faq)

## Connect to Active Directory

Before you can connect Defender for Identity to Active Directory, you'll need at least one Directory Services account. For information about how to create and configure that account, see [Microsoft Defender for Identity Directory Service Account recommendations](directory-service-accounts.md).

After you've created that account, provide the account details in the **Directory Service accounts** settings in Microsoft 365 Defender. For information on how to configure the settings, see [Microsoft Defender for Identity Directory Services account in Microsoft 365 Defender](directory-service-accounts.md#configure-directory-services-account-in-microsoft-365-defender).

## Add a sensor

From the **Sensors** page, you can add a new sensor, and download the installer. For instructions on how to download the sensor package, and install the sensors, see [Install a sensor](install-sensor.md).

## Configure the sensor

After you've installed the sensors, you'll need to configure them. For information on how to configure the sensors, see [Configure a sensor](configure-sensor-settings.md).

## Manage action accounts

After the sensors are configured, you'll want to add action accounts. For information on how to add action accounts, see [Manage action accounts](manage-action-accounts.md).

## Next steps

- [Install the Microsoft Defender for Identity sensor](install-sensor.md)
