---
title: Change ATA configuration - ATA Center certificate  | Microsoft Advanced Threat Analytics
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
# Change ATA configuration - ATA Center certificate

>[!div class="step-by-step"]
[« ATA Center server IP address](modifying-ata-config-centerip.md)
[ATA Console IP address »](modifying-ata-config-consoleip.md)

## <a name="ATA_modify_centercert"></a>Change the ATA Center certificate
If your certificates expire and need to be renewed or replaced after installing the new certificate in the local computer store on the ATA Center server, replace the certificate by following this two stage process:

-   First stage – Update the certificate you want the ATA Center service to use. At this point the ATA Center service is still bound to the original certificate. When the ATA Gateways sync their configuration they will have two potential certificates that will be valid for mutual authentication. As long as the ATA Gateway can connect using the original certificate, it will not try the new one.

-   Second stage – After all the ATA Gateways synced with the updated configuration, you can activate the new certificate that the ATA Center service is bound to. When you activate the new certificate, the ATA Center service will bind to the certificate. ATA Gateways will not be able to properly mutually authenticate the ATA Center service and will attempt to authenticate the second certificate. After connecting to the ATA Center service, the ATA Gateway will pull down the latest configuration and will have a single certificate for the ATA Center. (Unless you  started the process again.)

> [!NOTE]
> -   If an ATA Gateway was offline during the first stage and never got the updated configuration, you will need to manually update the configuration JSON file on the ATA Gateway.
> -   The certificate that you are using must be trusted by the ATA Gateways.
> -   If you need to deploy a new ATA Gateway after activating the new certificate, you need to download the ATA Gateway Setup package again.

1.  Open the ATA Console.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![ATA configuration settings icon](media/ATA-config-icon.JPG)

3.  Select **ATA Center**.

4.  Under **Certificate**, select one of the certificates in the list.

5.  Click **Save**.

6.  You will see a notification of how many ATA Gateways synced to the latest configuration.

7.  After all the ATA Gateways synced, click **Activate** to activate the new certificate.

8.  Ensure that all the ATA Gateways are able to sync their configurations after the change was activated.

>[!div class="step-by-step"]
[« ATA Center server IP address](modifying-ata-config-centerip.md)
[ATA Console IP address »](modifying-ata-config-consoleip.md)

## See Also
- [Working with the ATA Console](/advanced-threat-analytics/understand/working-with-ata-console)
- [Install ATA](install-ata.md)
- [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
