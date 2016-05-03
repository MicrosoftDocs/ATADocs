---
# required metadata

title: Change ATA configuration - ATA Console IP address | Microsoft Advanced Threat Analytics
description: Describes how to change the IP address of the ATA Console, used to create a shortcut to the ATA Console on the ATA Gateways.
keywords:
author: rkarlin
manager: stevenpo
ms.date: 04/28/2016
ms.topic: article
ms.prod: identity-ata
ms.service: advanced-threat-analytics
ms.technology: security
ms.assetid: 50118465-df34-4e04-b0cc-48808b6a96b1

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

# Change ATA configuration - ATA Console IP address

>[!div class="step-by-step"]
[« ATA Center certificate](modifying-ata-config-centercert.md)
[IIS certificate »](modifying-ata-config-iiscert.md)

## Change the ATA Console IP address
By default, the ATA Console URL is the IP address selected for the ATA Console IP address when you installed the ATA Center.

The URL is used in the following scenarios:

-   Installation of ATA Gateways – When an ATA Gateway is installed, it registers itself with the ATA Center. This registration process is accomplished by connecting to the ATA Console. If you enter an FQDN for the ATA Console URL, you need to ensure that the ATA Gateway can resolve the FQDN to the IP address that the ATA Console is bound to in IIS. Additionally, the URL is used to create the shortcut to the ATA Console on the ATA Gateways.

-   Alerts – When ATA sends out a SIEM or email alert, it includes a link to the suspicious activity. The host portion of the link is the ATA Console URL setting.

-   If you installed a certificate from your internal Certification Authority (CA), you will probably want to match the URL to the subject name in the certificate so users will not get a warning message when connecting to the ATA Console.

-   Using an FQDN for the ATA Console URL allows you to modify the IP address that is used by IIS for the ATA Console without breaking alerts that have been sent out in the past or needing to re-download the ATA Gateway package again. You only need to update the DNS with the new IP address.

> [!NOTE]
> After modifying the ATA Console URL, you should download the ATA Gateway Setup package before installing new ATA Gateways.

If you need to modify the IP address used by IIS for the ATA Console, follow these steps on the ATA Center server.

1.  Install the IP address on the ATA Center server.

2.  Open Internet Information Services (IIS) Manager.

3.  Expand the name of the server and expand **Sites**.

4.  Select the Microsoft ATA Console site and in the **Actions** pane click **Bindings**.

    ![ATA Console bindings action image](media/ATA-console-change-IP-bindings.jpg)

5.  Select **HTTP** and click **Edit** to select the new IP address. Do the same for **HTTPS** selecting the same IP address.

    ![Edit site binding image](media/ATA-change-console-IP.jpg)

6.  In the **Action** pane click **Restart** under **Mange Website**.

7.  Open an Administrator command prompt and type the following commands to update the HTTP.SYS driver:

    -   To add the new IP address - `netsh http add iplisten ipaddress=newipaddress`

    -   To see that the new address is being used - `netsh http show iplisten`

    -   To delete the old IP address – `netsh http delete iplisten ipaddress=oldipaddress`

8.  If the ATA Console URL is still using an IP address, update the ATA Console URL to the new IP address and download the ATA Gateway Setup package before deploying new ATA Gateways.

9. If the ATA Console URL is an FQDN, update the DNS with the new IP address for the FQDN.

>[!div class="step-by-step"]
[« ATA Center certificate](modifying-ata-config-centercert.md)
[IIS certificate »](modifying-ata-config-iiscert.md)


## See Also
- [Working with the ATA Console](/advanced-threat-analytics/understand-explore/working-with-ata-console)
- [Install ATA](install-ata.md)
- [Check out the ATA forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
