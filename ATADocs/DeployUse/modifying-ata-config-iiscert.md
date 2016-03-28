---
title: Change ATA configuration - IIS certificate | Microsoft Advanced Threat Analytics
ms.custom:
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology:
  - security
ms.tgt_pltfrm: na
ms.topic: article
author: Rkarlin
---
# Change ATA configuration - IIS certificate

>[!div class="step-by-step"]
[« ATA Console IP address](modifying-ata-config-consoleip.md)
[Domain connectivity password »](modifying-ata-config-dcpassword.md)

## <a name="ATA_modify_IIScert"></a>Change the IIS certificate
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
- [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
