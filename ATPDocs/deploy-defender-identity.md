---
title: Deploy Defender for Identity with Microsoft 365 Defender
description: Learn how to deploy Microsoft Defender for Identity using Microsoft 365 Defender
ms.date: 01/23/2022
ms.topic: how-to
---

# Deploy Microsoft Defender for Identity with Microsoft 365 Defender

Learn how to deploy Microsoft Defender for Identity using Microsoft 365 Defender.

> [!IMPORTANT]
> Currently, [!INCLUDE [Product short](includes/product-short.md)] data centers are deployed in Europe, UK, North America/Central America/Caribbean and Asia. Your instance is created automatically in the data center that is geographically closest to your Azure Active Directory (Azure AD). Once created, [!INCLUDE [Product short](includes/product-short.md)] instances aren't movable.

## Prerequisites

- A [[!INCLUDE [Product long](includes/product-long.md)] license](/defender-for-identity/technical-faq#licensing-and-privacy).
- You need to be a [global administrator or security administrator on the tenant](/azure/active-directory/users-groups-roles/directory-assign-admin-roles#available-roles) to access the Identity section on the Microsoft 365 Defender portal.
- Review the [[!INCLUDE [Product short](includes/product-short.md)] architecture](architecture.md) article.
- Review the [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md) article.

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

After you've created that account, provide the account details in the **Directory Service accounts** settings in Microsoft 365 Defender. For information on how to configure the settings, see [Microsoft Defender for Identity Directory Services account in Microsoft 365 Defender](/microsoft-365/security/defender-identity/directory-service-accounts).

## Add a sensor

From the **Sensors** page, you can add a new sensor, and download the installer. For instructions on how to add and download the sensor package, see [Add a sensor](/microsoft-365/security/defender-identity/sensor-health#add-a-sensor).

## Install the sensor

Once you've downloaded the sensor package, you'll need to install it on your domain controllers and [AD FS servers](active-directory-federation-services.md). For instructions on how to install the sensor, see [Install the Microsoft Defender for Identity sensor](install-step4.md).

## Next steps

- [Sensor health and settings](/microsoft-365/security/defender-identity/sensor-health).

## Join the community

Have more questions, or an interest in discussing [!INCLUDE [Product short](includes/product-short.md)] and related security with others? Join the [[!INCLUDE [Product short](includes/product-short.md)] Community](<https://aka.ms/MDIcommunity>) today!
