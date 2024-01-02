---
title: Remediation actions
description: Learn how to respond to compromised users with remediation actions in Microsoft Defender for Identity
ms.date: 08/28/2023
ms.topic: conceptual
---

# Remediation actions in Microsoft Defender for Identity

Applies to:

- Microsoft Defender for Identity
- Microsoft Defender XDR

Microsoft Defender for Identity allows you to respond to compromised users by disabling their accounts or resetting their password. After taking action on users, you can check on the activity details in the action center.

The response actions on users are available directly from the user page, the user side panel, the advanced hunting page, or in the action center.

Watch the following video to learn more about remediation actions in Defender for Identity:

<br>

> [!VIDEO https://www.microsoft.com/videoplayer/embed/RE4U7Pe]


## Prerequisites

To perform any of the [supported actions](#supported-actions), you need to:

- Configure the account that Microsoft Defender for Identity will use to perform them.  For more information, see [Microsoft Defender for Identity action accounts](manage-action-accounts.md).

- Be signed into Microsoft Defender XDR to with relevant permissions. For Active Directory recommendations, you'll need a **Security Administrator** or **Security Operator** role. For Entra ID recommendations, you'll need a **Global Administrator** role.

## Supported actions

The following actions can be performed directly on the user account:

- **Disable user in Active Directory**: This will temporarily prevent a user from signing in to the on-premises network. This can help prevent compromised users from moving laterally and attempting to exfiltrate data or further compromise the network.

- **Reset user password** – This will prompt the user to change their password on the next logon, ensuring that this account can't be used for further impersonation attempts.

Depending on your Microsoft Entra ID roles, you may see additional Microsoft Entra ID remediations, such as resetting user passwords and confirming that a user is compromised. For more information, see [Remediate risks and unblock users](/entra/id-protection/howto-identity-protection-remediate-unblock).

> [!NOTE]
> By default, the Microsoft Defender for Identity sensor installed on a domain controller will impersonate the *LocalSystem* account of the domain controller and perform the above actions. However, you can change this default behavior by [setting up a gMSA account](manage-action-accounts.md) and scope the permissions as you need.


Currently, this feature requires the account signed into Microsoft Defender XDR to possess the **Security Administrator** or **Security Operator** roles.

## Related videos

[Remediation actions in Defender for Identity](https://www.microsoft.com/videoplayer/embed/RE4U7Pe)

## See also

[Microsoft Defender for Identity action accounts](manage-action-accounts.md)
