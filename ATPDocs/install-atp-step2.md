---
# required metadata

title: Install Azure Advanced Threat Protection - Step 2 | Microsoft Docs
description: Step two of installing Azure ATP helps you configure the domain connectivity settings on your Azure ATP cloud service
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/21/2017
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: ae8a95f0-278c-4a12-ae69-14282364fba1

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: itargoet
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*



# Install Azure ATP - Step 2

>[!div class="step-by-step"]
[« Step 1](install-atp-step1.md)
[Step 3 »](install-atp-step3.md)

## Step 2. Provide a username and password to connect to your Active Directory Forest

The first time you open the Azure ATP workspace portal, the following screen appears:

![Azure ATP welcome stage 1](media/directory-services.png)

> [!IMPORTANT]
> The user credentials here must be for a user account in the on-premises Active Directory. 


1.  Enter the following information and click **Save**:

    |Field|Comments|
    |---------|------------|
    |**Username** (required)|Enter the read-only Active Directory user name, for example: **ATPuser**.|
    |**Password** (required)|Enter the password for the read-only user, for example: **Pencil1**.|
    |**Domain** (required)|Enter the domain for the read-only user, for example, **contoso.com**. **Note:** It is important that you enter the complete FQDN of the domain where the user is located. For example, if the user’s account is in domain corp.contoso.com, you need to enter `corp.contoso.com` not contoso.com|

3. In the workspace portal, click **Download sensor setup and install the first sensor** to continue.


>[!div class="step-by-step"]
[« Step 1](install-atp-step1.md)
[Step 3 »](install-atp-step3.md)


## See Also
- [Azure ATP sizing tool](http://aka.ms/aatpsizingtool)
- [Configure event collection](configure-event-collection.md)
- [Azure ATP prerequisites](atp-prerequisites.md)
- [Check out the ATP forum!](https://aka.ms/azureatpcommunity)