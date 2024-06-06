---
title: Microsoft Defender for Identity – privacy
description: Learn how Microsoft Defender for Identity collects data in a manner that protects personal privacy.
ms.date: 06/06/2024
ms.topic: conceptual
#customerIntent: To learn how Microsoft Defender for Identity collects data in a manner that protects personal privacy.
---

# Privacy with Microsoft Defender for Identity

This article describes how Microsoft Defender for Identity collects data in a manner that protects personal privacy.

## What data is collected?

Microsoft Defender for Identity monitors information generated from your organization's Active Directory, network activities, and event activities to detect suspicious activity. The monitored activity information enables Defender for Identity to help you determine the validity of each potential threat and correctly triage and respond.

For more information see: [Microsoft Defender for Identity monitored activities](monitored-activities.md).

## Data location

Defender for Identity operates in the Microsoft Azure data centers in the following locations:

- European Union
- United Kingdom
- United States
- Australia
- Switzerland
- Singapore

Customer data collected by the service might be stored as follows:

- Your workspace is automatically created in data center that's geographically closest to your Microsoft Entra ID. Once created, Defender for Identity workspaces can't be moved to another data center. Your workspace's data center is listed in the Microsoft Defender portal, under **Settings** > **Identity** > **About** > **Geolocation**.

- A geographic location as defined by the data storage rules of an online service, if the online service is used by Defender for Identity to process such data.

## Data retention

Data from Microsoft Defender for Identity is retained for 180 days, visible across the portal.  

Your data is kept and is available to you while the license is under grace period or suspended mode. At the end of this period, that data will be erased from Microsoft's systems to make it unrecoverable, no later than 180 days from contract termination or expiration. 

## Data sharing

Defender for Identity shares data, including customer data, among any of the following Microsoft products that are also licensed by the customer:

- Microsoft Defender XDR
- Microsoft Defender for Cloud Apps
- Microsoft Defender for Endpoint
- Microsoft Defender for Cloud
- Microsoft Sentinel
- Microsoft Security Exposure Management

## Relevant content

For more information, see:

- The [Microsoft Service Trust portal](https://www.microsoft.com/en-us/trust-center/product-overview)
- [Microsoft 365 Enterprise GDPR Compliance](https://www.microsoft.com/en-us/trust-center/product-overview)

<!--
## Search for and identify personal data

In Defender for Identity, you can view identifiable personal data from the [Microsoft 365 Defender portal](https://security.microsoft.com) using the search bar.

Search for a specific user or computer, and select the entity to bring you to the user or computer [profile page](/defender-for-identity/investigate-assets). The profile provides you with comprehensive details about the entity from Active Directory, including network activity related to that entity and its history.

Defender for Identity personal data is gathered from Active Directory through the Defender for Identity sensor and stored in a backend database.

## Update personal data

Defender for Identity's personal user data is derived from the user's object in the Active Directory of the organization. Therefore, changes made to the user profile in the organization AD are reflected in Defender for Identity.

## Delete personal data

- After a user is deleted from the organization's Active Directory, Defender for Identity automatically deletes the user profile and any related network activity within a year. You can also [delete](/defender-for-identity/manage-security-alerts#review-suspicious-activities-on-the-attack-time-line) any security alerts that contain personal data.

- **Read-only** permissions on the **Deleted Objects** container are recommended. To learn more about how the **Deleted Objects** container permission is used by the Defender for Identity service, see the Deleted Objects container recommendation in [Defender for Identity Permissions required for the Directory Service account](directory-service-accounts.md#permissions-required-for-the-dsa).

## Export personal data

In Defender for Identity you have the ability to [export](/defender-for-identity/manage-security-alerts#review-suspicious-activities-on-the-attack-time-line) security alert information to Excel. This function also exports the personal data.

## Audit personal data

Defender for Identity implements the audit of personal data changes, including the deleting and exporting of personal data records. Audit trail retention time is 90 days. Auditing in Defender for Identity is a back-end feature and not accessible to customers.


To related content: [Defender for Identity FAQ](/defender-for-identity/technical-faq#licensing-and-privacy)
-->