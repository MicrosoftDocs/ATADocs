---
title: Modifying ATA Configuration
ms.custom: 
  - ATA
ms.prod: identity-ata
ms.reviewer: na
ms.suite: na
ms.technology: 
  - security
ms.tgt_pltfrm: na
ms.topic: article
ms.assetid: bcf0f7d3-8027-45c0-8002-19f71fcb30a6
author: Rkarlin
---
# Modifying ATA Configuration
If you need to update or change your configuration after initial installation and deployment of ATA, use this topic for guidance before modifying the following:

-   [Modifying the IP address used by the ATA Center server](#ATA_modify_centerIP)

-   [Modifying the ATA Center certificate](#ATA_modify_centercert)

-   [Modifying the ATA Console IP address](#ATA_modify_consoleIP)

-   [Modifying the IIS certificate](#ATA_modify_IIScert)

-   [Modifying the domain connectivity password](#ATA_modify_dcpassword)

-   [Changing the name of the capture network adapter](#ATA_modify_nicname)

## Modifying the ATA Center configuration
After the initial deployment, modifications to the ATA Center should be made carefully. Use the following procedures when updating the IP address and port or the certificate.

### <a name="ATA_modify_centerIP"></a>Modifying the IP address used by the ATA Center server
If you need to change the ATA Center IP address and port or certificate, take the following into consideration.

The ATA Gateways locally store the IP address of the ATA Center to which they need to connect. On a regular basis, they connect to the ATA Center and pull down configuration changes. Making a change to how the ATA Gateways connect to the ATA Center is done is two stages.

-   First stage – Update the IP address and port that the ATA Center service you want the ATA Center service to use. At this point the ATA Center is still listening on the original IP address and the next time the ATA Gateway syncs its configuration it will have two IP addresses for the ATA Center. As long as the ATA Gateway can connect using the original (first) IP address it will not try the new IP address and port.

-   Second stage – After all the ATA Gateways have synced with the updated configuration, activate the new IP address and port that the ATA Center listens on. When you activate the new IP address the ATA Center service will bind to the new IP address. ATA Gateways will not be able to connect to the original address and now will attempt to connect with the second (new) IP address they have for the ATA Center. After connecting to the ATA Center with the new IP address the ATA Gateway will pull down the latest configuration and will have a single IP address for the ATA Center. (Unless you started the process again.)

> [!NOTE]
> -   If an ATA Gateway was offline during the first stage and never got the updated configuration, you will need to manually update the configuration JSON file on the ATA Gateway.
> -   If the new IP address is installed on the ATA Center server, you can select it from the list of IP addresses when making the change. However, if for some reason you cannot install the IP address on the ATA Center server you can select custom IP address and add it manually. You will not be able to activate the new IP address until the IP address is installed on the server.
> -   If you need to deploy a new ATA Gateway after activating the new IP address, you need to download the ATA Gateway Setup package again.

1.  Open the ATA Console.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![](../Image/ATA_config_icon.JPG)

3.  Select **ATA Center**.

4.  Under **ATA Center Service IP address: port**, select one of the existing IP addresses or select **Add custom IP address** and enter an IP address.

5.  Click **Save**.

6.  You will see a notification of how many ATA Gateways have synced to the latest configuration.

    ![](../Image/ATA_chge_IP_after_clicking_save.png)

7.  After all the ATA Gateways have synced, click **Activate** to activate the new IP address.

    > [!NOTE]
    > If you entered a custom IP address, you will not be to click **Activate** until you installed the IP address on the ATA Center.

8.  Ensure that all the ATA Gateways are able to sync their configurations after the change was activated. The notification bar will indicate how many ATA Gateways successfully synced their configuration.

### <a name="ATA_modify_centercert"></a>Modifying the ATA Center certificate
If your certificates expire and need to be renewed or replaced after installing the new certificate in the local computer store on the ATA Center server, replace the certificate by following this two stage process:

-   First stage – Update the certificate you want the ATA Center service to use. At this point the ATA Center service is still bound to the original certificate. When the ATA Gateways sync their configuration they will have two potential certificates that will be valid for mutual authentication. As long as the ATA Gateway can connect using the original certificate, it will not try the new one.

-   Second stage – After all the ATA Gateways synced with the updated configuration, you can activate”the new certificate that the ATA Center service is bound to. When you activate the new certificate, the ATA Center service will bind to the certificate. ATA Gateways will not be able to properly mutually authenticate the ATA Center service and will attempt to authenticate the second certificate. After connecting to the ATA Center service, the ATA Gateway will pull down the latest configuration and will have a single certificate for the ATA Center. (Unless you  started the process again.)

> [!NOTE]
> -   If an ATA Gateway was offline during the first stage and never got the updated configuration, you will need to manually update the configuration JSON file on the ATA Gateway.
> -   The certificate that you are using must be trusted by the ATA Gateways.
> -   If you need to deploy a new ATA Gateway after activating the new certificate, you need to download the ATA Gateway Setup package again.

1.  Open the ATA Console.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![](../Image/ATA_config_icon.JPG)

3.  Select **ATA Center**.

4.  Under **Certificate**, select one of the certificates in the list.

5.  Click **Save**.

6.  You will see a notification of how many ATA Gateways synced to the latest configuration.

7.  After all the ATA Gateways synced, click **Activate** to activate the new certificate.

8.  Ensure that all the ATA Gateways are able to sync their configurations after the change was activated.

### <a name="ATA_modify_consoleIP"></a>Modifying the ATA Console IP address
By default, the ATA Console URL is the IP address selected for the ATA Console IP address when you installed the ATA Center.

The URL is used in the following scenarios:

-   Installation of ATA Gateways – When an ATA Gateway is installed, it registers itself with the ATA Center. This registration process is accomplished by connecting to the ATA Console. If you enter an FQDN for the ATA Console URL, you need to ensure that the ATA Gateway can resolve the FQDN to the IP address that the ATA Console is bound to an IIS. Additionally, the URL is used to create the shortcut to the ATA Console on the ATA Gateways.

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

    ![](../Image/ATA_console_change_IP_bindings.jpg)

5.  Select **HTTP** and click **Edit** to select the new IP address. Do the same for **HTTPS** selecting the same IP address.

    ![](../Image/ATA_change_console_IP.jpg)

6.  In the **Action** pane click **Restart**  under **Mange Website**.

7.  Open an Administrator command prompt and type the following commands to update the HTTP.SYS driver:

    -   To add the new IP address - `netsh http add iplisten ipaddress=newipaddress`

    -   To see that the new address is being used - `netsh http show iplisten`

    -   To delete the old IP address – `netsh http delete iplisten ipaddress=oldipaddress`

8.  If the ATA Console URL is still using an IP address, update the ATA Console URL to the new IP address and download the ATA Gateway Setup package before deploying new ATA Gateways.

9. If the ATA Console URL is an FQDN, update the DNS with the new IP address for the FQDN.

## <a name="ATA_modify_IIScert"></a>Modifying the IIS certificate
In the console, you can select and change the certificate for the ATA Center service, but you can't change the certificate used by IIS.

If you want to change it, use the following procedure:

> [!NOTE]
> After modifying the IIS Certificate you should download the ATA Gateway Setup package before installing new ATA Gateways.

If you need to modify the certificate used by IIS for the ATA Center, follow these steps from the ATA Center server.

1.  Install the new certificate on the ATA Center server.

2.  Open Internet Information Services (IIS) Manager.

3.  Expand the name of the server and expand **Sites**.

4.  Select the Microsoft ATA Console site and in the **Actions** pane click **Bindings**.

    ![](../Image/ATA_console_change_IP_bindings.jpg)

5.  Select **HTTPS** and click **Edit**.

6.  Under **SSL certificate**, select the new certificate.

7.  Download the ATA Gateway Setup package before installing a new ATA Gateway.

## <a name="ATA_modify_dcpassword"></a>Modifying the domain connectivity password
If you modify the Domain Connectivity Password, make sure that the password you enter is correct. If it is not, the ATA Service will stop running on the ATA Gateways.

If you suspect that this happened, on the ATA Gateway, look at the Microsoft.Tri.Gateway-Errors.log file for the following:
`The supplied credential is invalid.`

To correct this, follow this procedure to update the Domain Connectivity password on the ATA Gateway:

1.  Open the ATA Console on the ATA Gateway.

2.  Select the settings option on the toolbar and select **Configuration**.

    ![](../Image/ATA_config_icon.JPG)

3.  Select **ATA Gateway**.

    ![](../Image/ATA_GW_change_DC_password.JPG)

4.  Under **Domain Connectivity Settings**, change the password.

5.  Click **Save**.

6.  After changing the password, manually check that the ATA Gateway service is running on the ATA Gateway servers.

## <a name="ATA_modify_nicname"></a>Changing the name of the ATA Gateway capture network adapter
If you change the name of the network adapter that is currently configured as a Capture network adapter, this will cause the ATA Gateway server not to start. In order to smoothly change the name without ending ATA Gateway connectivity, follow this process:

1.  In the ATA Gateway configuration page, unselect the network adapter  you want to rename, and select another network adapter as the capture network adapter in its place. This can be an interim network adapter or even the management network adapter. During this time, ATA will not capture the domain controller's port-mirrored traffic. Save the new configuration.

2.  On the ATA Gateway, rename the network adapter, by opening your Control Panel and selecting Network Connections.

3.  Then, go back into the ATA console's ATA Gateway configuration page. You may have to refresh the page, and then you should see the network adapter with the new name in the list. Unselect the adapter you selected in step 1, and select the newly named adapter. Finally, save the new configuration.

If you renamed your network adapter without following this process, your ATA Gateway won’t start and you will get this error on the ATA Gateway inMicrosoft.Tri.Gateway-Errors.log log file. In the example below, **Capture** would be the original name of the network adapter you set:

`Error [NetworkListener] Microsoft.Tri.Infrastructure.ExtendedException: Unavailable network adapters [UnavailableCaptureNetworkAdapterNames=Capture]`

To correct this problem, rename the network adapter  back to the name it was originally called when you set up ATA, and then go through the process described above for changing the name.

## See Also
[Working with the ATA Console](../Topic/Working_with_the_ATA_Console.md)
 [Install ATA](../Topic/Install_ATA.md)
 [For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)

