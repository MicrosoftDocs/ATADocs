---
title: Microsoft Defender for Identity – privacy
description: Learn how Microsoft Defender for Identity collects data in a manner that protects personal privacy.
ms.date: 06/06/2024
ms.topic: conceptual
#customerIntent: To learn how Microsoft Defender for Identity collects data in a manner that protects personal privacy.
---

# Privacy with Microsoft Defender for Identity

This article describes how Microsoft Defender for Identity collects data in a manner that protects personal privacy.

[!INCLUDE [gdpr-hybrid-note](../includes/gdpr-hybrid-note.md)]

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
- Microsoft Security Exposure Management (public preview)

## Data management

- **Personal data updates**: Personal user data in Defender for Identity is derived from the user's object in the organization's Active Directory, and can't be updated directly in Defender for Identity.

- **Personal data deletion**: After a user is deleted from the organization's Active Directory, Defender for Identity automatically deletes the user profile and any related network activity within a year.

    We recommend adding **Read-only** permissions on the **Deleted Objects** container. For more information, see [Grant required DSA permissions](directory-service-accounts.md#grant-required-dsa-permissions).

- **Personal data exports**: Export personal data to Excel using the same method as exporting security alert information. For more information, see [Review suspicious activities on the attack timeline](manage-security-alerts.md#review-suspicious-activities-on-the-attack-time-line).
- 
- **Search for personal data**: Use the [Microsoft Defender portal](https://security.microsoft.com) search bar to search for identifiable personal data, such as a specific user or computer. For more information, see [Investigate assets](investigate-assets.md).

- **Data auditing**: Defender for Identity implements the audit of personal data changes, including the deleting and exporting of personal data records. Audit trail retention time is 90 days. Auditing in Defender for Identity is a back-end feature and not accessible to customers.

## Related content

For more information, see:

- The [Microsoft Service Trust portal](https://www.microsoft.com/en-us/trust-center/product-overview)
- [Microsoft 365 Enterprise GDPR Compliance](https://www.microsoft.com/en-us/trust-center/product-overview)
