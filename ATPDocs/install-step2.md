---
title: Connect Microsoft Defender for Identity to Active Directory quickstart
description: Step two of installing Microsoft Defender for Identity helps you configure the domain connectivity settings on your Defender for Identity cloud service
ms.date: 10/26/2020
ms.topic: quickstart
---

# Quickstart: Connect to your Active Directory Forest

> [!NOTE]
> The experience described in this page can also be accessed at <https://security.microsoft.com> as part of Microsoft 365 Defender. The supporting documents for the new experience can be found [here](/microsoft-365/security/defender-identity/sensor-health#configure-directory-services-account). For more information about Microsoft Defender for Identity and when other features will be available in Microsoft 365 Defender, see [Microsoft Defender for Identity in Microsoft 365 Defender](defender-for-identity-in-microsoft-365-defender.md).

In this quickstart, you'll connect [!INCLUDE [Product long](includes/product-long.md)] to Active Directory (AD) to retrieve data about users and computers. If you're connecting multiple forests, see the [Multi-forest support](multi-forest.md) article.

## Prerequisites

- A [[!INCLUDE [Product short](includes/product-short.md)] instance](install-step1.md).
- Review the [[!INCLUDE [Product short](includes/product-short.md)] prerequisites](prerequisites.md) article.
- At least one of the following directory services accounts with read access to all objects in the monitored domains:
  - A **standard** AD user account and password. Required for sensors running Windows Server 2008 R2 SP1.
  - A **group Managed Service Account** (gMSA). Requires Windows Server 2012 or above.
  All sensors must have permissions to retrieve the gMSA account's password. For information about creating a gMSA account, see [Set up a gMSA account](#how-to-set-up-a-gmsa-account).

    > [!NOTE]
    >
    > - For sensor machines running Windows Server 2012 and above, we recommend using a **gMSA** account for its improved security and automatic password management.
    > - If you have multiple sensors, some running Windows Server 2008 and others running Windows Server 2012 or above, in addition to the recommendation to use a **gMSA** account, you must also use at least one **standard** AD user account.
    > - By default, Defender for Identity supports up to 30 credentials. If you want to add more credentials, contact Defender for Identity support.

### How to set up a gMSA account

1. Read the group managed service accounts [prerequisites](/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts#BKMK_gMSA_Req) carefully.

2. Create a new security group containing all the domain controllers that will run the sensors (running Windows Server 2012 or above).
    - If you're planning to use one gMSA for the whole forest, you can add all the domain controllers to a universal group.
    - If all the domain controllers are Windows 2012 and above, you can use the built-in **Domain Controllers** group.

3. Create the gMSA account using the cmdlet as explained in [this article](/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts#BKMK_CreateGMSA). For the **PrincipalsAllowedToRetrieveManagedPassword** parameter, enter the name of the security group you created in the previous step. This will grant the group permissions to retrieve the gMSA's password.

>[!NOTE]
>If the user rights assignment policy **Log on as a service** is configured for this domain controller, impersonation will fail unless the gMSA account is granted the **Log on as a service** permission. For more information, see [Sensor failed to retrieve group Managed Service Account (gMSA) credentials](troubleshooting-known-issues.md#cause-2).

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
