---
title: Data security and privacy policy
description: Provides links to information about how to delete private information and personal data from Microsoft Defender for Identity.
ms.date: 01/29/2023
ms.topic: conceptual
---

# Microsoft Defender for Identity data security and privacy

[!INCLUDE [Handle personal data](../includes/gdpr-intro-sentence.md)]

## Search for and identify personal data

In Defender for Identity, you can view identifiable personal data from the [Microsoft 365 Defender portal](https://security.microsoft.com) using the search bar.

Search for a specific user or computer, and select the entity to bring you to the user or computer [profile page](/defender-for-identity/investigate-assets). The profile provides you with comprehensive details about the entity from Active Directory, including network activity related to that entity and its history.

Defender for Identity personal data is gathered from Active Directory through the Defender for Identity sensor and stored in a backend database.

## Data sharing

Defender for Identity shares data, including customer data, among the following Microsoft products also licensed by the customer.

- Microsoft 365 Defender
- Microsoft Defender for Cloud Apps
- Microsoft Defender for Endpoint
- Microsoft Defender for Cloud
- Microsoft Sentinel

## Update personal data

Defender for Identity's personal user data is derived from the user's object in the Active Directory of the organization. Therefore, changes made to the user profile in the organization AD are reflected in Defender for Identity.

## Delete personal data

- After a user is deleted from the organization's Active Directory, Defender for Identity automatically deletes the user profile and any related network activity within a year. You can also [delete](/defender-for-identity/manage-security-alerts#review-suspicious-activities-on-the-attack-time-line) any security alerts that contain personal data.

- **Read-only** permissions on the **Deleted Objects** container are recommended. To learn more about how the **Deleted Objects** container permission is used by the Defender for Identity service, see the Deleted Objects container recommendation in [Defender for Identity Permissions required for the Directory Service account](directory-service-accounts.md#permissions-required-for-the-dsa).

## Export personal data

In Defender for Identity you have the ability to [export](/defender-for-identity/manage-security-alerts#review-suspicious-activities-on-the-attack-time-line) security alert information to Excel. This function also exports the personal data.

## Audit personal data

Defender for Identity implements the audit of personal data changes, including the deleting and exporting of personal data records. Audit trail retention time is 90 days. Auditing in Defender for Identity is a back-end feature and not accessible to customers.

## Additional resources

- For information about Defender for Identity trust and compliance, see the [Service Trust portal](https://servicetrust.microsoft.com/ViewPage/GDPRGetStarted) and the [Microsoft 365 Enterprise GDPR Compliance site](/microsoft-365/compliance/gdpr?view=o365-worldwide&preserve-view=true).

> [!IMPORTANT]
> Currently, Defender for Identity data centers are deployed in Europe, UK, North America/Central America/Caribbean, Australia East and Asia. Your workspace is created automatically in the data center that is geographically closest to your Azure Active Directory (Azure AD). Once created, Defender for Identity workspaces aren't movable.

## See also

- More information about privacy can be found in the [Defender for Identity FAQ](/defender-for-identity/technical-faq#licensing-and-privacy)
