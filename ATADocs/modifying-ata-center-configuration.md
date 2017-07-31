---
# required metadata

title: Change Advanced Threat Analytics ATA Center config | Microsoft Docs
description: Describes how to change the IP address, port, console URL or certificate of your ATA Center.
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 7/31/2017
ms.topic: article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: 93b27f15-f7e5-49bb-870a-d81d09dfe9fc

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Advanced Threat Analytics version 1.8*



# Modifying the ATA Center configuration


After the initial deployment, modifications to the ATA Center should be made carefully. Use the following procedures when updating the IP address and port, the console URL, and the certificate.

## The ATA Center IP address

The ATA Gateways locally store the IP address of the ATA Center to which they need to connect. On a regular basis, they connect to the ATA Center and pull down configuration changes. Making a change to how the ATA Gateways connect to the ATA Center is done in two stages.

-   First stage – Update the IP address and port that you want the ATA Center service to use. At this point, the ATA Center still listens on the original IP address. The next time the ATA Gateway syncs its configuration, it will have two IP addresses for the ATA Center. As long as the ATA Gateway can connect using the original (first) IP address, it does not try the new IP address and port.

-   Second stage – After all the ATA Gateways have synced with the updated configuration, activate the new IP address and port that the ATA Center listens on. When you activate the new IP address, the ATA Center service binds to the new IP address. ATA Gateways will not be able to connect to the original address and attempt to connect with the second (new) IP address listed for the ATA Center. After connecting to the ATA Center with the new IP address, the ATA Gateway pulls down the latest configuration and has a single IP address for the ATA Center. (Unless you started the process again.)

> [!NOTE]
> -   If an ATA Gateway was offline during the first stage and never got the updated configuration, manually update the configuration JSON file on the ATA Gateway.
> -   If the new IP address is installed on the ATA Center server, you can select it from the list of IP addresses when making the change. However, if for some reason you cannot install the IP address on the ATA Center server, select custom IP address and add it manually. You cannot activate the new IP address until the IP address is installed on the server.
> -   If you need to deploy a new ATA Gateway after activating the new IP address, you need to download the ATA Gateway Setup package again.

## The Console URL

The URL is used in the following scenarios:

-   Installation of ATA Gateways – When an ATA Gateway is installed, it registers itself with the ATA Center. This registration process is accomplished by connecting to the ATA Console. If you enter an FQDN for the ATA Console URL, ensure that the ATA Gateway can resolve the FQDN to the IP address bound to the ATA Console.

-   Alerts – When ATA sends out a SIEM or email alert, it includes a link to the suspicious activity. The host portion of the link is the ATA Console URL setting.

-   If you installed a certificate from your internal Certification Authority (CA), match the URL to the subject name in the certificate. This prevents users from getting a warning message when connecting to the ATA Console.

-   Using an FQDN for the ATA Console URL allows you to modify the IP address that is used by ATA Console without breaking previous alerts  or downloading the ATA Gateway package again. You only need to update the DNS with the new IP address.

> [!NOTE]
> After modifying the ATA Console URL, you should download the ATA Gateway Setup package before installing new ATA Gateways.

## The ATA Center certificate

After a certificate is installed in the ATA Center's local computer store, you may need to renew or replace the certificate. Replace the certificate by following this process:

-   First stage – Before the current certificate expires, create a new certificate. Add the new certificate to the ATA Center service to use. The ATA Center service is still bound to the original certificate. When the ATA Gateways sync their configuration, they have two potential certificates that are valid for mutual authentication. As long as the ATA Gateway can connect using the original certificate, it does not try the new one.

-   Second stage – After all the ATA Gateways synced with the updated configuration, you can activate the new certificate that the ATA Center service is bound to. When you activate the new certificate, the ATA Center service binds to the new certificate. ATA Gateways will not be able to properly mutually authenticate the ATA Center service and attempts to authenticate the second certificate. After connecting to the ATA Center service, the ATA Gateway will pull down the latest configuration and will have a single certificate for the ATA Center. (Unless you started the process again.)

> [!NOTE]
> -   If an ATA Gateway was offline during the first stage and never got the updated configuration, manually update the configuration JSON file on the ATA Gateway.
> -   The certificate that you are using must be trusted by the ATA Gateways.
> -   The certificate is also used for the ATA Console, so it should match the ATA Console address to avoid browser warnings.
> -   If you need to deploy a new ATA Gateway after activating the new certificate, you need to download the ATA Gateway Setup package again.

## Changing the ATA Center configuration

1.  Open the ATA Console.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![ATA configuration settings icon](media/ATA-config-icon.png)

3.  Select **Center**.

  ![Change ATA configuration](media/change-center-config.png)

4.  Under **URL**, select **Add custom DNS name / IP address** and the new DNS or IP address, or under **Certificate** select the new certificate.

5.  Click **Save**.

6.  A notification lets you know how many ATA Gateways have synced to the latest configuration.

   	>[!IMPORTANT]
	>Before activating the new configuration, validate that all the ATA Gateways are synced with the latest configuration. Activating the new configuration before all the ATA Gateways are synced may cause the ATA Gateway to stop functioning as expected. If any of the ATA Gateways are not synced, you get this error when you click Activate:


7.  After all the ATA Gateways have synced, click **Activate** to activate the new IP address or certificate.

    > [!NOTE]
    > If you entered a custom IP address, you cannot click **Activate** until you installed the IP address on the ATA Center.

8.  Ensure that all the ATA Gateways are able to sync their configurations after the change was activated. The notification bar indicates how many ATA Gateways successfully synced their configuration.




## See Also
- [Working with the ATA Console](working-with-ata-console.md)
- [Check out the ATA forum!](https://aka.ms/ata-forum)
