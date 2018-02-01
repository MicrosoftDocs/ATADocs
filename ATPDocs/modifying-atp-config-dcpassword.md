---
# required metadata

title: Change Azure Advanced Threat Protection config - domain connectivity password | Microsoft Docs
description: Describes how to change the Domain Connectivity Password on the Azure ATP Standalone Sensor.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 11/7/2017
ms.topic: article
ms.prod:
ms.service: azure-advanced-threat-protection
ms.technology:
ms.assetid: e7f065fa-1ad1-4e87-bd80-99cc695efbf5

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



# Change Azure ATP configuration - domain connectivity password



## Change the domain connectivity password
If you modify the Domain Connectivity Password, make sure that the password you enter is correct. If it is not, the Azure ATP Standalone Sensor service stops running on the Azure ATP Standalone Sensors.

If you suspect that this happened, on the Azure ATP Standalone Sensor, look at the Microsoft.Tri.Gateway-Errors.log file for the following errors:
`The supplied credential is invalid.`

To correct this, follow this procedure to update the Domain Connectivity password on the Azure ATP cloud service:

1.  Open the Azure ATP Console on the Azure ATP cloud service.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![Azure ATP configuration settings icon](media/atp-config-menu.png)

3.  Select **Directory Services**.

    ![Azure ATP Standalone Sensor change password image](media/dirctory-services.png)

4.  Under **Password**, change the password.

    If the Azure ATP cloud service has connectivity to the domain, use the **Test Connection** button to validate the credentials

5.  Click **Save**.

6.  After changing the password, manually check that the Azure ATP Standalone Sensor service is running on the Azure ATP Standalone Sensor servers.



## See Also
- [Working with the Azure ATP Console](working-with-ata-console.md)
- [Check out the Azure ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
