---
title: Connect Microsoft Defender for Identity to Active Directory quickstart
description: Step two of installing Microsoft Defender for Identity helps you configure the domain connectivity settings on your Defender for Identity cloud service
ms.date: 10/26/2020
ms.topic: quickstart
---

# Quickstart: Connect to your Active Directory Forest

> [!NOTE]
> The experience described in this page can also be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender. The supporting documents for the new experience can be found [here](/microsoft-365/security/defender-identity/directory-service-accounts). For more information about Microsoft Defender for Identity and when other features will be available in Microsoft 365 Defender, see [Microsoft Defender for Identity in Microsoft 365 Defender](defender-for-identity-in-microsoft-365-defender.md).

In this quickstart, you'll connect [!INCLUDE [Product long](includes/product-long.md)] to Active Directory (AD) to retrieve data about users and computers. If you're connecting multiple forests, see the [Multi-forest support](multi-forest.md) article.

## Prerequisites

- A [[!INCLUDE [Product short](includes/product-short.md)] instance](install-step1.md).
- Review the [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md) article.
- At least one directory services accounts with read access to all objects in the monitored domains. For instructions on how to create the directory service account, see [Directory Service Account recommendations](directory-service-accounts.md).

## Provide a username and password to connect to your Active Directory Forest

The first time you open the [!INCLUDE [Product short](includes/product-short.md)] portal, the following screen appears:

![Welcome stage 1, Directory Services settings.](media/directory-services.png)

1. Enter the following information and select **Save**:

    |Field|Comments|
    |---|---|
    |**Username** (required)|Enter the read-only AD username. For example: **DefenderForIdentityUser**. You must use a **standard** AD user or gMSA account. **Don't** use the UPN format for your username.<br />**NOTE:** We recommend that you avoid using accounts assigned to specific users.|
    |**Password** (required for standard AD user account)|For AD user account only, enter the password for the read-only user. For example: *Pencil1*.|
    |**Group managed service account** (required for gMSA account)|For gMSA account only, select **Group managed service account**.|
    |**Domain** (required)|Enter the domain for the read-only user. For example: **contoso.com**. It's important that you enter the complete FQDN of the domain where the user is located. For example, if the user's account is in domain corp.contoso.com, you need to enter `corp.contoso.com` not contoso.com|

1. In the [!INCLUDE [Product short](includes/product-short.md)] portal, click **Download sensor setup and install the first sensor** to continue.

## Next steps

> [!div class="step-by-step"]
> [« Step 1 - Create [!INCLUDE [Product short](includes/product-short.md)] instance](install-step1.md)
> [Step 3 - Download the sensor setup »](install-step3.md)

## Join the Community

Have more questions, or an interest in discussing [!INCLUDE [Product short](includes/product-short.md)] and related security with others? Join the [[!INCLUDE [Product short](includes/product-short.md)] Community](<https://aka.ms/MDIcommunity>) today!
