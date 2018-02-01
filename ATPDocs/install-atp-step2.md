---
# required metadata

title: Install Azure Advanced Threat Protection - Step 2 | Microsoft Docs
description: Step two of installing Azure ATP helps you configure the domain connectivity settings on your Azure ATP cloud service server
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: get-started-article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: ae8a95f0-278c-4a12-ae69-14282364fba1

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Advanced Threat Protection*



# Install Azure ATP - Step 2

>[!div class="step-by-step"]
[« Step 1](install-ata-step1.md)
[Step 3 »](install-ata-step3.md)

## Step 2. Provide a Username and Password to connect to your Active Directory Forest

The first time you open the Azure ATP Console, the following screen appears:

![Azure ATP welcome stage 1](media/directory-services.png)

1.  Enter the following information and click **Save**:

    |Field|Comments|
    |---------|------------|
    |**Username** (required)|Enter the read-only user name, for example: **ATAuser**.|
    |**Password** (required)|Enter the password for the read-only user, for example: **Pencil1**.|
    |**Domain** (required)|Enter the domain for the read-only user, for example, **contoso.com**. **Note:** It is important that you enter the complete FQDN of the domain where the user is located. For example, if the user’s account is in domain corp.contoso.com, you need to enter `corp.contoso.com` not contoso.com|

2. You can click **Test connection** to test connectivity to the domain and check that the credentials supplied provide access. This works if the Azure ATP cloud service has connectivity to the domain. 	

    After it is saved, the welcome message in the Console will change to the following message:
![Azure ATP welcome stage 1 finished](media/ATA_1.7-welcome-provide-username-finished.png)

3. In the Console, click **Download Gateway setup and install the first Gateway** to continue.


>[!div class="step-by-step"]
[« Step 1](install-ata-step1.md)
[Step 3 »](install-ata-step3.md)


## See Also
## Related Videos
- [Azure ATP Deployment Overview](https://channel9.msdn.com/Shows/Microsoft-Security/Overview-of-ATP-Deployment-in-10-Minutes)
- [Choosing the right Azure ATP Standalone Sensor type](https://channel9.msdn.com/Shows/Microsoft-Security/ATP-Deployment-Choose-the-Right-Gateway-Type)


## See Also
- [Azure ATP POC deployment guide](http://aka.ms/atapoc)
- [Azure ATP sizing tool](http://aka.ms/trisizingtool)
- [Check out the Azure ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
- [Configure event collection](configure-event-collection.md)
- [Azure ATP prerequisites](ata-prerequisites.md)
