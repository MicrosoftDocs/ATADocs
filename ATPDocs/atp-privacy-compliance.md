---
# required metadata

title: Azure Advanced Threat Protection personal data policy| Microsoft Docs
description: Provides links to information about how to delete private information and personal data from Azure ATP.
keywords:
author: mlottner
ms.author: mlottner
manager: barbkess
ms.date: 10/04/2018
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: 224e629a-0e82-458c-bb03-b67070a9241d


# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: ophirp
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Azure ATP data security and privacy

[!INCLUDE [Handle personal data](../includes/gdpr-intro-sentence.md)]

## Search for and identify personal data 

In Azure Advanced Threat Protection you can view identifiable personal data from the [Azure ATP portal](workspace-portal.md) using the [search bar](workspace-portal.md#search-bar). 

Search for a specific user or computer, and click on the entity to bring you to the user or computer [profile page](entity-profiles.md). The profile provides you with comprehensive details about the entity from Active Directory, including network activity related to that entity and its history.

Azure ATP personal data is gathered from Active Directory through the Azure ATP sensor and stored in a backend database.

## Update personal data 

Azure ATP's personal user data is derived from the user’s object in the Active Directory of the organization. Therefore, changes made to the user profile in the organization AD are reflected in Azure ATP.


## Delete personal data 

After a user is deleted from the organization's Active Directory, Azure ATP automatically deletes the user profile and any related network activity within a year. You can also [delete](working-with-suspicious-activities.md#review-suspicious-activities-on-the-attack-time-line) any security alerts that contain personal data. 

## Export personal data 

In Azure ATP you have the ability to [export](working-with-suspicious-activities.md#review-suspicious-activities-on-the-attack-time-line) security alert information to Excel. This function also exports the personal data. 
 
## Audit personal data

Azure ATP implements the audit of personal data changes, including the deleting and exporting of personal data records. Audit trail retention time is 90 days. Auditing in Azure ATP is a back-end feature and not accessible to customers.
 
## Additional resources

- For information about Azure ATP trust and compliance, see the [Service Trust portal](https://servicetrust.microsoft.com/ViewPage/GDPRGetStarted) and the [Microsoft 365 Enterprise GDPR Compliance site](https://docs.microsoft.com/microsoft-365/compliance/compliance-solutions-overview).
