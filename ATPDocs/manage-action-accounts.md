---
title: Manage action accounts
description: Learn how to configure the Directory Service Account (DSA) to work with Microsoft Defender for Identity.
ms.date: 01/17/2022
ms.topic: how-to
---

# Microsoft Defender for Identity action accounts

Defender for Identity now allows you to create action accounts. These accounts are used to allow you to take actions on users directly from Defender for Identity.

We recommend you create the gMSA account Defender for Identity will use to take actions now, to benefit from the Actions features when they're available.

>[!NOTE]
> As those actions become available, we will announce them in the [What's new in Microsoft Defender for Identity](whats-new.md) page.

## Create and configure the action account

1. On your domain controller, create a new gMSA account, following the instructions in [Getting started with Group Managed Service Accounts](/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts).

1. Grant the required permissions to the gMSA account.
    1. Open **Active Directory Users and Computers**.
    1. Right-click the relevant domain or OU, and select **Properties**.
        ![Select properties of domain or OU.](media/domain-properties.png)
    1. Go the **Security** tab and select **Advanced**.
        ![Advanced security settings.](media/advanced-security.png)
    1. Select **Add** and browse to your service accounts. Make sure **Service Accounts** is marked in **Object types**.
        ![Select service accounts as object types.](media/object-types.png)
    1. Select **Descendant User objects** and choose the following permissions:
        - Permissions to enable force password reset:
            - Reset password
            - Read pwdLastSet
            - Write pwdLastSet
        - Permissions to disable user:
            - Read userAccountControl
            - Write userAccountControl
    1. Select **Descendant Group objects** and choose the following permissions:
        - Permissions to remove user from a group:
            - Applies to Descendant Group object
            - Read members
            - Write members
    1. Select **OK**.

## Add the gMSA account in the Microsoft 365 Defender portal

1. Go to the [Microsoft 365 Defender portal](https://security.microsoft.com).
1. Go to **Settings** -> **Identities**.
1. Under **Microsoft Defender for Identity**, select **Manage action accounts**.
1. Select **+Create new account** to add your gMSA account.
1. Provide the account name and domain, and select **Save**.
1. Your action account will be listed on the **Manage action accounts** page.

      ![Create action account.](media/manage-action-accounts.png)

## See also

- [Connect to your Active Directory Forest](install-step2.md)
- [Microsoft Defender for Identity Directory Service Account recommendations](directory-service-accounts.md)
