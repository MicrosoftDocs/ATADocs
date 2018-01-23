---
# required metadata

title: Change Azure Threat Protection config - domain connectivity password | Microsoft Docs
description: Describes how to change the Domain Connectivity Password on the ATP Gateway.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 4a25561b-a5ed-44aa-9b72-366976b3c72a

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Threat Protection *



# Change ATP configuration - domain connectivity password



## Change the domain connectivity password
If you modify the Domain Connectivity Password, make sure that the password you enter is correct. If it is not, the ATP Gateway service stops running on the ATP Gateways.

If you suspect that this happened, on the ATP Gateway, look at the Microsoft.Tri.Gateway-Errors.log file for the following errors:
`The supplied credential is invalid.`

To correct this, follow this procedure to update the Domain Connectivity password on the ATP Center:

1.  Open the ATP Console on the ATP Center.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![ATP configuration settings icon](media/ATP-config-icon.png)

3.  Select **Directory Services**.

    ![ATP Gateway change password image](media/ATP-GW-change-DC-password.png)

4.  Under **Password**, change the password.

    If the ATP Center has connectivity to the domain, use the **Test Connection** button to validate the credentials

5.  Click **Save**.

6.  After changing the password, manually check that the ATP Gateway service is running on the ATP Gateway servers.



## See Also
- [Working with the ATP Console](working-with-ata-console.md)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
