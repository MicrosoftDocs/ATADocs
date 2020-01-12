---
# required metadata

title: Configure SAM-R to enable lateral movement path detection in Advanced Threat Analytics | Microsoft Docs
description: Describes how to configure SAM-R to enable lateral movement path detection in Advanced Threat Analytics (ATA)
keywords:
author: shsagir
ms.author: shsagir
manager: rkarlin
ms.date: 09/08/2019
ms.topic: conceptual
ms.prod: advanced-threat-analytics
ms.technology:
ms.assetid: 7597ed25-87f5-472c-a496-d5f205c9c391


# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Install ATA - Step 9

*Applies to: Advanced Threat Analytics version 1.9*

> [!div class="step-by-step"]
> [« Step 8](install-ata-step7.md)

> [!NOTE]
> Before enforcing any new policy, always make sure that your environment remains secure, without impacting application compatibility by first enabling and verifying your proposed changes in audit mode. 

## Step 9. Configure SAM-R required permissions

The [lateral movement path](use-case-lateral-movement-path.md) detection relies on queries that identify local admins on specific machines. These queries are performed using the SAM-R protocol, via the ATA Service account created in [Step 2. Connect to AD](install-ata-step2.md).
 
To ensure that Windows clients and servers allow the ATA service account to perform this SAM-R operation, a modification to your **Group policy** must be made that adds the ATA service account in addition to the configured accounts listed in the **Network access** policy. This group policy should be applied for every device in your organization. 

1. Locate the policy:

   - Policy Name: Network access - Restrict clients allowed to make remote calls to SAM
   - Location: Computer configuration, Windows settings, Security settings, Local policies, Security options
  
   ![Locate the policy](./media/samr-policy-location.png)

2. Add the ATA service to the list of approved accounts able to perform this action on your modern Windows systems.
 
   ![Add the service](./media/samr-add-service.png)

3. The **ATA Service** (the ATA service created during installation) now has the proper privileges to perform SAM-R in the environment.

 For more information on SAM-R and Group Policy, see [Network access: Restrict clients allowed to make remote calls to SAM](https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls).


> [!div class="step-by-step"]
> [« Step 8](install-ata-step7.md)

## See Also
- [ATA POC deployment guide](https://aka.ms/atapoc)
- [ATA sizing tool](https://aka.ms/atasizingtool)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [ATA prerequisites](ata-prerequisites.md)
