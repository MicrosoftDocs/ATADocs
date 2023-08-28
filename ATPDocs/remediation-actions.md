---
title: Remediation actions
description: Learn how to respond to compromised users with remediation actions in Microsoft Defender for Identity
ms.date: 08/28/2023
ms.topic: conceptual
---

# Remediation actions in Microsoft Defender for Identity

Applies to:

- Microsoft Defender for Identity
- Microsoft 365 Defender

Microsoft Defender for Identity allows you to respond to compromised users by disabling their accounts or resetting their password. After taking action on users, you can check on the activity details in the action center.

The response actions on users are available directly from the user page, the user side panel, the advanced hunting page, or in the action center.

Watch the following video to learn more about remediation actions in Defender for Identity:

<br>

> [!VIDEO https://www.microsoft.com/en-us/videoplayer/embed/RE4U7Pe]


## Prerequisites

To perform any of the [supported actions](#supported-actions), you need to:

- Configure the account that Microsoft Defender for Identity will use to perform them.  For more information, see [Microsoft Defender for Identity action accounts](deploy/manage-action-accounts.md).

- Be signed into Microsoft 365 Defender to with a **Security Administrator** or **Security Operator** role.

## Supported actions

The following actions can be performed directly on the user account:

- **Disable user in Active Directory**: This will temporarily prevent a user from logging in to the on-premises network. This can help prevent compromised users from moving laterally and attempting to exfiltrate data or further compromise the network.

- **Suspend user in Azure Active Directory**: This will temporarily prevent a user from logging in to Azure Active Directory. This can help prevent compromised users from attempting to exfiltrate data and minimizes the time between Disable user in Active Directory and the sync of this status to the cloud.

- **Reset user password** – This will prompt the user to change their password on the next logon, ensuring that this account can't be used for further impersonation attempts. 

    For users with the **Password never expires** flag turned on, the password reset will only take place once the flag is removed.

> [!NOTE]
> By default, the Microsoft Defender for Identity sensor installed on a domain controller will impersonate the *LocalSystem* account of the domain controller and perform the above actions. However, you can change this default behavior by [setting up a gMSA account](manage-action-accounts.md) and scope the permissions as you need.


## Next step

[Microsoft Defender for Identity action accounts](deploy/manage-action-accounts.md)

