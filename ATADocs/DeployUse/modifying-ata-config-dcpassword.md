---
ms.custom:
title: Change ATA configuration - domain connectivity password | Microsoft Advanced Threat Analytics
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
# Change ATA configuration - domain connectivity password

>[!div class="step-by-step"]
[« IIS certificate](modifying-ata-config-iiscert.md)
[Name of the capture network adapter »](modifying-ata-config-nicname.md)

## <a name="ATA_modify_dcpassword"></a>Change the domain connectivity password
If you modify the Domain Connectivity Password, make sure that the password you enter is correct. If it is not, the ATA Service will stop running on the ATA Gateways.

If you suspect that this happened, on the ATA Gateway, look at the Microsoft.Tri.Gateway-Errors.log file for the following:
`The supplied credential is invalid.`

To correct this, follow this procedure to update the Domain Connectivity password on the ATA Gateway:

1.  Open the ATA Console on the ATA Gateway.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![ATA configuration settings icon](media/ATA-config-icon.JPG)

3.  Select **ATA Gateway**.

    ![ATAA Gateway change password image](media/ATA-GW-change-DC-password.JPG)

4.  Under **Domain Connectivity Settings**, change the password.

5.  Click **Save**.

6.  After changing the password, manually check that the ATA Gateway service is running on the ATA Gateway servers.

>[!div class="step-by-step"]
[« IIS certificate](modifying-ata-config-iiscert.md)
[Name of the capture network adapter »](modifying-ata-config-nicname.md)

## See Also
- [Working with the ATA Console](/ATA/understand/working-with-ata-console)
- [Install ATA](install-ata.md)
- [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
