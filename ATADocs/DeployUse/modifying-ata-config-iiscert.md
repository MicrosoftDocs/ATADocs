---
# required metadata

title: Change ATA configuration - IIS certificate | Microsoft Advanced Threat Analytics
description: Describes how to change certificate used by IIS for the ATA Center.
keywords:
author: rkarlin
manager: stevenpo
ms.date: 04/28/2016
ms.topic: article
ms.prod: identity-ata
ms.service: advanced-threat-analytics
ms.technology: security
ms.assetid: e58a0390-57ef-4c68-a987-2e75e5f3d6b3

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Change ATA configuration - IIS certificate

>[!div class="step-by-step"]
[« ATA Console IP address](modifying-ata-config-consoleip.md)
[Domain connectivity password »](modifying-ata-config-dcpassword.md)

## Change the IIS certificate
In the console, you can select and change the certificate for the ATA Center service, but you can't change the certificate used by IIS.

If you want to change it, use the following procedure:

> [!NOTE]
> After modifying the IIS Certificate you should download the ATA Gateway Setup package before installing new ATA Gateways.

If you need to modify the certificate used by IIS for the ATA Center, follow these steps from the ATA Center server.

1.  Install the new certificate on the ATA Center server.

2.  Open Internet Information Services (IIS) Manager.A

3.  Expand the name of the server and expand **Sites**.

4.  Select the Microsoft ATA Console site and in the **Actions** pane click **Bindings**.

    ![ATA Console bindings actions](media/ATA-console-change-IP-bindings.jpg)

5.  Select **HTTPS** and click **Edit**.

6.  Under **SSL certificate**, select the new certificate.

7.  Download the ATA Gateway Setup package before installing a new ATA Gateway.

>[!div class="step-by-step"]
[« ATA Console IP address](modifying-ata-config-consoleip.md)
[Domain connectivity password »](modifying-ata-config-dcpassword.md)

## See Also
- [Working with the ATA Console](/advanced-threat-analytics/understand/working-with-ata-console)
- [Install ATA](install-ata.md)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
