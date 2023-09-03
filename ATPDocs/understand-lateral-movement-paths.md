---
title: Lateral movement paths in Microsoft Defender for Identity
description: This article describes the potential Lateral Movement Paths (LMPs) of Microsoft Defender for Identity
ms.date: 09/03/2023
ms.topic: conceptual
#CustomerIntent: As a Defender for Identity customers, I want to understand how to investigate LMPs so that I can identify suspicious access to sensitive accounts.
---

# What are lateral movement paths (LMPs) in Microsoft Defender for Identity?

Lateral movement is when an attacker uses non-sensitive accounts to gain access to sensitive accounts throughout your network, which may store sign-in credentials in accounts, groups, or machines. Once an attacker makes successful lateral moves towards your key targets, the attacker can also take advantage and gain access to your domain controllers.

For example, popular lateral movement methods are *Credential Theft* and *Pass the Ticket*. In both methods, your non-sensitive accounts are used by attackers for lateral moves by exploiting non-sensitive machines that share stored sign-in credentials in accounts, groups and machines with sensitive accounts.

Microsoft Defender for Identity provides lateral movement path (LMP) data for any identities discovered to be in a lateral movement path. In Defender for Identity, LMPs show as visual guides that help you understand how attackers might move laterally inside your network from non-sensitive to sensitive accounts. Use LMPs to help you mitigate and prevent lateral movement risks, and close attacker access before they can compromise your security.

## Where can I find Defender for Identity LMPs?

Identities discovered by Defender for Identity to be in a lateral movement path have details showing on the user page > **Observed in organization** > **Lateral movements** path. For example:

im:::image type="content" source="media/understand-lateral-movement-paths/path-sample.png" alt-text="Screenshot of a lateral movement path for a specific user.":::

The **Lateral movements** tab shows different information for each entity, depending on the entity's sensitivity:

- For sensitive users, the **Lateral movements** tab shows any potential LMP(s) leading to the selected entity
- For non-sensitive users and computers, the **Lateral movements** tab shows any potential LMP(s) related to the selected entity

By default, Defender for Identity shows the most recently discovered LMP. To view other LMPs, select other options from the **Select a date** or **Path initiator** menus. If no lateral movement path activity is detected for a specific entity, we recommend that you select to view a previous date and check for previous potential LMPs.

> [!TIP]
> When viewing a lateral movement path in Defender for Identity, learn as much as you can about the exposure of your sensitive user's credential. For example, follow the **Logged into by** arrows to see where the user signed in with their privileged credentials, and which other users signed into computers that created exposure and vulnerability.
>

LMP data is also shown in:

- **Security alert evidence lists**. For example, when a *Pass the Ticket* alert is issued, the source computer, compromised user and destination computer the stolen ticket was used from, are all part of the potential lateral movement path leading to a sensitive user.

- **Secure Score security assessments**. The [**Riskiest lateral movement paths (LMP)**](security-assessment-riskiest-lmp.md) security assessment helps you identify sensitive accounts with the riskiest lateral movement paths. Paths are considered risky if they have three or more non-sensitive accounts that can expose the sensitive account to credential theft.

    Use the recommendations listed in the **Riskiest lateral movement paths (LMP)** security assessment to remove the entity from a group, or remove local administrator permissions for the entity from the specified device.

### Discover LMPs with advanced hunting

To discover lateral movement path activities proactively, run an advanced hunting query. For example:

```kusto
IdentityDirectoryEvents
| where ActionTye == "Potential lateral movement path identified
| project TimeStamp, ActionType, Application, AccountName, AccountDomain, AccountSid, AccountDisplayName, DeviceName, AdditionalFields
```

For more information, see [Proactively hunt for threats with advanced hunting in Microsoft 365 Defender](/microsoft-365/security/defender/advanced-hunting-overview).

## Preventative best practices

It's never to late to prevent the next attack and remediate damage, even during the domain dominance phase of an attack. 

For example, while investigating a security alert like *Remote Code Execution*, if the alert is a true positive, your domain controller may already be compromised. Even in this case, LMPs inform on where the attacker gained privileges, and what path they used into your network. Used this way, LMPs can also offer key insights into how to remediate.

For example, we recommend using LMP data as follows to prevent future attacks:

- Make sure that sensitive users only use their administrator credentials when logging into hardened computers. For example, you might need to check if the admin user in the LMP actually needs access to the shared computer. If they do need access, make sure they sign in to the shared computer with a username and password other than their admin credentials.

- Make sure that your users don't have unnecessary administrative permissions. For example, check if everyone in the shared group actually requires admin rights on the exposed computer.

- Make sure that people only have access to necessary resources. For example, if there's a user that significantly widen's a sensitive user's exposure? Does that user need to be included in the group, or are there sub-groups you could create to minimize the lateral movement exposure?

- Make sure that your clients and servers allow Defender for Identity to properly perform the SAM-R operations required for lateral movement path detection. For more information, see [Configure Microsoft Defender for Identity to make remote calls to SAM](remote-calls-sam.md).

## Related videos

> [!VIDEO https://www.microsoft.com/en-us/videoplayer/embed/RWAOfW]

## Related content

- [Security alerts in Microsoft Defender for Identity](alerts-overview.md)
- [Security assessment: Riskiest lateral movement paths (LMP)](security-assessment-riskiest-lmp.md)
