---
# required metadata

title: Configure SAM-R to enable lateral movement path detection in Azure ATP | Microsoft Docs
description: Explains how to configure Azure ATP to make remote calls to SAM
keywords:
author: mlottner
ms.author: mlottner
manager: rkarlin
ms.date: 03/17/2019
ms.topic: conceptual
ms.collection: M365-security-compliance
ms.service: azure-advanced-threat-protection
ms.assetid: b09adce3-0fbc-40e3-a53f-31f57fe79ca3

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Configure Azure ATP to make remote calls to SAM
Azure ATP [lateral movement path](use-case-lateral-movement-path.md) detection relies on queries that identify local admins on specific machines. These queries are performed with the SAM-R protocol, using the Azure ATP Service account created during Azure ATP installation  [Step 2. Connect to AD](install-atp-step2.md).

## Configure SAM-R required permissions
To ensure Windows clients and servers allow your Azure ATP account to perform SAM-R, a modification to **Group Policy** must be made to add the Azure ATP service account in addition to the configured accounts listed in the **Network access** policy.

> [!Note]
> Before enforcing new policies such as this one, it is critical to make sure that your environment remains secure, and any changes will not impact your application compatibility. Do this by first enabling and then verifying compatibility of proposed changes in audit mode before making changes to your production environment.

1. Locate the policy:

   - Policy Name: Network access - Restrict clients allowed to make remote calls to SAM
   - Location: Computer configuration, Windows settings, Security settings, Local policies, Security options
  
   ![Locate the policy](./media/samr-policy-location.png)

2. Add the Azure ATP service to the list of approved accounts able to perform this action on your modern Windows systems.
 
   ![Add the service](./media/samr-add-service.png)

3. **AATP Service** (the Azure ATP service created during installation) now has the privileges needed to perform SAM-R in the environment.



For more on SAM-R and this Group Policy, see [Network access: Restrict clients allowed to make remote calls to SAM](https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls).



## See Also
- [Investigating lateral movement path attacks with Azure ATP](use-case-lateral-movement-path.md)
- [Check out the Azure ATP forum!](https://aka.ms/azureatpcommunity)
