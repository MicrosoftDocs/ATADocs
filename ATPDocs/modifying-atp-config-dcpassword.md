---
# required metadata

title: Change Azure Advanced Threat Protection config - domain connectivity password | Microsoft Docs
description: Describes how to change the Domain Connectivity Password on the Azure ATP Standalone Sensor.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 2/14/2018
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



# Change Azure ATP workspace portal configuration - domain connectivity password



## Change the domain connectivity password
If you modify the Domain Connectivity Password, make sure that the password you enter is correct. If it is not, the Azure ATP Standalone Sensor service stops running on the Azure ATP Standalone Sensors.

If you suspect that this happened, on the Azure ATP Standalone Sensor, look at the Microsoft.Tri.Sensor-Errors.log file for the following errors:
`The supplied credential is invalid.`

To correct this, follow this procedure to update the Domain Connectivity password on the Azure ATP workspace portal:

1.  Open the Azure ATP workspace portal on the by accessing the workspace URL.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![Azure ATP configuration settings icon](media/atp-config-menu.png)

3.  Select **Directory Services**.

    ![Azure ATP Standalone Sensor change password image](media/dirctory-services.png)

4.  Under **Password**, change the password.

 > [!NOTE]
 > Enter an Active Directory user and password here, not Azure Active Directory.

5.  Click **Save**.

6.  After changing the password, manually check that the Azure ATP Standalone Sensor service is running on the Azure ATP Standalone Sensor servers.



## See Also
- [Working with the Azure ATP workspace portal](working-with-ata-console.md)
- [Check out the Azure ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)
