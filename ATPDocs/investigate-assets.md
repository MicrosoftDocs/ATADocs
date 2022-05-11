---
title: Investigate assets
description: This article explains how to investigate suspicious users, computers, and devices with Microsoft Defender for Identity.
ms.date: 05/10/2022
ms.topic: conceptual
---

# Investigate assets

Microsoft Defender for Identity in Microsoft 365 Defender provides evidence when users, computers, and devices have performed suspicious activities or show signs of being compromised.  This article gives investigation suggestions to help you determine the risk to your organization, decide how to remediate, and determine the best way to prevent similar future attacks.

## Investigation steps for suspicious users

For information on how to view user profiles in Microsoft 365 Defender, see [Investigate users](/microsoft-365/security/defender/investigate-users).

If an alert or incident indicates that a user may be suspicious or compromised, check and investigate the user profile for the following details and activities:

1. Who is the [user](entity-profiles.md)?
    1. Is the user a [sensitive user](entity-tags.md) (such as admin, or on a watchlist, etc.)?
    1. What is their role within the organization?
    1. Are they significant in the organizational tree?

1. Suspicious activities to [investigate](investigate-entity.md):
    1. Does the user have other opened alerts in [!INCLUDE [Product short](includes/product-short.md)], or in other security tools such as Microsoft Defender for Endpoint, Microsoft Defender for Cloud and/or Microsoft Defender for Cloud Apps?
    1. Did the user have failed logons?
    1. Which resources did the user access?
    1. Did the user access high value resources?
    1. Was the user supposed to access the resources they accessed?
    1. Which devicess did the user sign in to?
    1. Was the user supposed to sign in to those devicess?
    1. Is there a [lateral movement path](use-case-lateral-movement-path.md) (LMP) between the user and a sensitive user?

Use the answers to these questions to determine if the account appears compromised or if the suspicious activities imply malicious actions.

## Investigation steps for suspicious devices

To access the device profile page, select the specific devices mentioned in the alert that you wish to investigate. To assist your investigation, alert evidence lists all devices and users connected to each suspicious activity.

Check and investigate the device profile for the following details and activities:

- What happened around the time of the suspicious activity?  
    1. Which user was logged in to the device?
    1. Does that user normally log into or access the source or destination device?
    1. Which resources were accessed? By which users?
      - If resources were accessed, were they high-value resources?
    1. Was the user supposed to access those resources?
    1. Did the user that accessed the device perform other suspicious activities?

- Additional suspicious activities to investigate:
    1. Were other alerts opened around the same time as this alert in [!INCLUDE [Product short](includes/product-short.md)], or in other security tools such as Microsoft Defender for Endpoint, Microsoft Defender for Cloud and/or Microsoft Defender for Cloud Apps?
    1. Were there failed logons?

- If Microsoft Defender for Endpoint integration is enabled, select the Microsoft Defender for Endpoint badge to further investigate the device. In Microsoft Defender for Endpoint, you can see which processes and alerts occurred around the same time as the alert.
  - Were any new programs deployed or installed?

Use the answers to these questions to determine if the device appears compromised or if the suspicious activities imply malicious actions.

## Next steps

- [Microsoft Defender for Identity Lateral Movement Paths (LMPs)](understand-lateral-movement-paths.md)

## Learn more

- Try our interactive guide: [Investigate and respond to attacks with Microsoft Defender for Identity](https://mslearn.cloudguides.com/guides/Investigate%20and%20respond%20to%20attacks%20with%20Microsoft%20Defender%20for%20Identity)
