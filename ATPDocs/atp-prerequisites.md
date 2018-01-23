---
# required metadata

title: Azure Threat Protection prerequisites | Microsoft Docs
description: Describes the requirements for a successful deployment of ATP in your environment
keywords:
author: rkarlin
ms.author: rkarlin
manager: mbaldwin
ms.date: 1/23/2018
ms.topic: get-started-article
ms.prod:
ms.service: advanced-threat-analytics
ms.technology:
ms.assetid: a5f90544-1c70-4aff-8bf3-c59dd7abd687

# optional metadata

#ROBOTS:
#audience:
#ms.devlang:
ms.reviewer: bennyl
ms.suite: ems
#ms.tgt_pltfrm:
#ms.custom:

---

*Applies to: Azure Threat Protection *



# ATP Prerequisites
This article describes the requirements for a successful deployment of ATP in your environment.

>[!NOTE]
> For information on how to plan resources and capacity, see [ATP capacity planning](ata-capacity-planning.md).


ATP is composed of the ATP Center, the ATP Gateway and/or the ATP Lightweight Gateway. For more information about the ATP components, see [ATP architecture](ata-architecture.md).

The ATP System works on active directory forest boundary and supports Forest Functional Level (FFL) of Windows 2003 and above.


[Before you start](#before-you-start): This section lists information you should gather and accounts and network entities you should have before starting ATP installation.

[ATP Center](#ata-center-requirements): This section lists ATP Center hardware, software requirements as well as settings  you need to configure on your ATP Center server.

[ATP Gateway](#ata-gateway-requirements): This section lists ATP Gateway hardware, software requirements as well as settings  you need to configure on your ATP Gateway servers.

[ATP Lightweight Gateway](#ata-lightweight-gateway-requirements): This section lists ATP Lightweight Gateway hardware, and software requirements.

[ATP Console](#ata-console): This section lists browser requirements for running the ATP Console.

![ATP architecture diagram](media/ATP-architecture-topology.jpg)

## Before you start
This section lists information you should gather and accounts and network entities you should have before starting ATP installation.


-   User account and password with read access to all objects in the monitored domains.

    > [!NOTE]
    > If you have set custom ACLs on various Organizational Units (OU) in your domain, make sure that the selected user has read permissions to those OUs.

-   Do not install Microsoft Message Analyzer on an ATP Gateway or Lightweight Gateway. The Message Analyzer driver conflicts with the ATP Gateway and  Lightweight Gateway drivers. If you run Wireshark on ATP Gateway, you will need to restart the Microsoft Azure Threat Protection Gateway Service after you have stopped the Wireshark capture. If not, the Gateway stops capturing traffic. Running Wireshark on an ATP Lightweight Gateway does not interfere with the ATP Lightweight Gateway.

-    Recommended: User should have read-only permissions on the Deleted Objects container. This allows ATP to detect bulk deletion of objects in the domain. For information about configuring read-only permissions on the Deleted Objects container, see the **Changing permissions on a deleted object container** section in the [View or Set Permissions on a Directory Object](https://technet.microsoft.com/library/cc816824%28v=ws.10%29.aspx) article.

-   Optional: A user account of a user who has no network activities. This account is configured as the ATP Honeytoken user. To configure the Honeytoken user, you need the SID of the user account, not the username. For more information, see [Configure IP address exclusions and Honeytoken user](install-ata-step7.md).

-   Optional: In addition to collecting and analyzing network traffic to and from the domain controllers, ATP can use Windows events 4776, 4732, 4733, 4728, 4729, 4756 and 4757 to further enhance ATP Pass-the-Hash, Brute Force, Modification to sensitive groups and Honey Tokens detections. These events can be received from your SIEM or by setting Windows Event Forwarding from your domain controller. Events collected provide ATP with additional information that is not available via the domain controller network traffic.


## ATP Center requirements
This section lists the requirements for the ATP Center.
### General
The ATP Center supports installation on a server running Windows Server 2012 R2 or Windows Server 2016. 
The ATP Center can be installed on a server that is a member of a domain or workgroup.

Before installing ATP Center running Windows 2012 R2, confirm that the following update has been installed: [KB2919355](https://support.microsoft.com/kb/2919355/).

You can check by running the following Windows PowerShell cmdlet: `[Get-HotFix -Id kb2919355]`.

Installation of the ATP Center as a virtual machine is supported. 

>[!NOTE] 
> When running as a virtual machine dynamic memory or any other memory ballooning feature is not supported.

If you run the ATP Center as a virtual machine, shut down the server before creating a new checkpoint to avoid potential database corruption.

### Server specifications

When working on a physical server, the ATP database necessitates that you **disable** Non-uniform memory access (NUMA) in the BIOS. Your system may refer to NUMA as Node Interleaving, in which case you have to **enable** Node Interleaving in order to disable NUMA. For more information, see your BIOS documentation.<br>
For optimal performance, set the **Power Option** of the ATP Center to **High Performance**.<br>
The number of domain controllers you are monitoring and the load on each of the domain controllers dictates the server specifications needed. For more information, see [ATP capacity planning](ata-capacity-planning.md).


### Time synchronization

The ATP Center server, the ATP Gateway servers, and the domain controllers must have time synchronized to within five minutes of each other.


### Network adapters

You should have the following set:
-   At least one network adapter (if using physical server in VLAN environment, it is recommended to use two network adapters)

-   An IP address for communication between the ATP Center and the ATP Gateway that is encrypted using SSL on port 443. (The ATP service binds to all IP addresses that the ATP Center has on port 443.)

### Ports
The following table lists the minimum ports that have to be opened for the ATP Center to work properly.

|Protocol|Transport|Port|To/From|Direction|
|------------|-------------|--------|-----------|-------------|
|**SSL** (ATP Communications)|TCP|443|ATP Gateway|Inbound|
|**HTTP** (optional)|TCP|80|Company Network|Inbound|
|**HTTPS**|TCP|443|Company Network and ATP Gateway|Inbound|
|**SMTP** (optional)|TCP|25|SMTP Server|Outbound|
|**SMTPS** (optional)|TCP|465|SMTP Server|Outbound|
|**Syslog** (optional)|TCP|514|Syslog server|Outbound|
|**LDAP**|TCP and UDP|389|Domain controllers|Outbound|
|**LDAPS** (optional)|TCP|636|Domain controllers|Outbound|
|**DNS**|TCP and UDP|53|DNS servers|Outbound|
|**Kerberos** (optional if domain joined)|TCP and UDP|88|Domain controllers|Outbound|
|**Netlogon** (optional if domain joined)|TCP and UDP|445|Domain controllers|Outbound|
|**Windows Time** (optional if domain joined)|UDP|123|Domain controllers|Outbound|

> [!NOTE]
> LDAP is required to test the credentials to be used between the ATP Gateways and the domain controllers. The test is performed from the ATP Center to a domain controller to test the validity of these credentials, after which the ATP Gateway uses LDAP as part of its normal resolution process.

### Certificates

To ease the installation of ATP, you can install self-signed certificates during installation. Post deployment you should replace the self-signed with a certificate from an internal Certification Authority to be used by the ATP Center.


Make sure the ATP Center and ATP Gateways have access to your CRL distribution point. If they don't have Internet access, follow [the procedure to manually import a CRL](https://technet.microsoft.com/library/aa996972%28v=exchg.65%29.aspx), taking care to install the all the CRL distribution points for the whole chain.

The certificate must have:
-	A private key
-	A provider type of either Cryptographic Service Provider (CSP) or Key Storage Provider (KSP)
-	A public key length of 2048 bits
-	A value set for KeyEncipherment and ServerAuthentication usage flags

For example, you can use the standard **Web server** or **Computer** templates.

> [!WARNING]
> - The process of renewing an existing certificate is not supported. The only way to renew a certificate is by creating a new certificate and configuring ATP to use the new certificate.


> [!NOTE]
> - If you are going to access the ATP Console from other computers, ensure that those computers trust the certificate being used by ATP Center otherwise you get a warning page that there is a problem with the website's security certificate before getting to the log in page.
> - Starting with ATP  the ATP Gateways and Lightweight Gateways are managing their own certificates and need no administrator interaction to manage them.

## ATP Gateway requirements
This section lists the requirements for the ATP Gateway.
### General
The ATP Gateway supports installation on a server running Windows Server 2012 R2 or Windows Server 2016 (Include server core).
The ATP Gateway can be installed on a server that is a member of a domain or workgroup.
The ATP Gateway can be used to monitor Domain Controllers with Domain Functional Level of Windows 2003 and above.

Before installing ATP Gateway running Windows 2012 R2, confirm that the following update has been installed: [KB2919355](https://support.microsoft.com/kb/2919355/).

You can check by running the following Windows PowerShell cmdlet: `[Get-HotFix -Id kb2919355]`.


For information on using virtual machines with the ATP Gateway, see [Configure port mirroring](configure-port-mirroring.md).

> [!NOTE]
> A minimum of 5 GB of space is required and 10 GB is recommended. This includes space needed for the ATP binaries, [ATP logs, and [performance logs](troubleshooting-ata-using-perf-counters.md).

### Server specifications
For optimal performance, set the **Power Option** of the ATP Gateway to **High Performance**.<br>
An ATP Gateway can support monitoring multiple domain controllers, depending on the amount of network traffic to and from the domain controllers.

>[!NOTE] 
> When running as a virtual machine dynamic memory or any other memory ballooning feature is not supported.

For more information about the ATP Gateway hardware requirements, see [ATP capacity planning](ata-capacity-planning.md).

### Time synchronization
The ATP Center server, the ATP Gateway servers, and the domain controllers must have time synchronized to within five minutes of each other.

### Network adapters
The ATP Gateway requires at least one Management adapter and at least one Capture adapter:

-   **Management adapter** - used for communications on your corporate network. This adapter should be configured with the following settings:

    -   Static IP address including default gateway

    -   Preferred and alternate DNS servers

    -   The **DNS suffix for this connection** should be the DNS name of the domain for each domain being monitored.

        ![Configure DNS suffix in advanced TCP/IP settings](media/ATP-DNS-Suffix.png)

        > [!NOTE]
        > If the ATP Gateway is a member of the domain, this may be configured automatically.

-   **Capture adapter** - used to capture traffic to and from the domain controllers.

    > [!IMPORTANT]
    > -   Configure port mirroring for the capture adapter as the destination of the domain controller network traffic. For more information, see [Configure port mirroring](configure-port-mirroring.md). Typically, you need to work with the networking or virtualization team to configure port mirroring.
    > -   Configure a static non-routable IP address for your environment with no default gateway and no DNS server addresses. For example, 1.1.1.1/32. This ensures that the capture network adapter can capture the maximum amount of traffic and that the management network adapter is used to send and receive the required network traffic.

### Ports
The following table lists the minimum ports that the ATP Gateway requires configured on the management adapter:

|Protocol|Transport|Port|To/From|Direction|
|------------|-------------|--------|-----------|-------------|
|LDAP|TCP and UDP|389|Domain controllers|Outbound|
|Secure LDAP (LDAPS)|TCP|636|Domain controllers|Outbound|
|LDAP to Global Catalog|TCP|3268|Domain controllers|Outbound|
|LDAPS to Global Catalog|TCP|3269|Domain controllers|Outbound|
|Kerberos|TCP and UDP|88|Domain controllers|Outbound|
|Netlogon|TCP and UDP|445|Domain controllers|Outbound|
|Windows Time|UDP|123|Domain controllers|Outbound|
|DNS|TCP and UDP|53|DNS Servers|Outbound|
|NTLM over RPC|TCP|135|All devices on the network|Outbound|
|NetBIOS|UDP|137|All devices on the network|Outbound|
|SSL|TCP|443|ATP Center|Outbound|
|Syslog (optional)|UDP|514|SIEM Server|Inbound|

> [!NOTE]
> As part of the resolution process done by the ATP Gateway, the following ports need to be open inbound on devices on the network from the ATP Gateways.
>
> -   NTLM over RPC (TCP Port 135)
> -   NetBIOS (UDP port 137)

## ATP Lightweight Gateway requirements
This section lists the requirements for the ATP Lightweight Gateway.
### General
The ATP Lightweight Gateway supports installation on a domain controller running Windows Server 2008 R2 SP1 (not including Server Core), Windows Server 2012, Windows Server 2012 R2, Windows Server 2016 (including Core but not Nano).

The domain controller can be a read-only domain controller (RODC).

Before installing ATP Lightweight Gateway on a domain controller running Windows Server 2012 R2,
 confirm that the following update has been installed: [KB2919355](https://support.microsoft.com/kb/2919355/).

You can check by running the following Windows PowerShell cmdlet: `[Get-HotFix -Id kb2919355]`

If the installation is for Windows server 2012 R2 Server Core, the following update should also be installed:
 [KB3000850](https://support.microsoft.com/help/3000850/november-2014-update-rollup-for-windows-rt-8.1%2c-windows-8.1%2c-and-windows-server-2012-r2).

 You can check by running the following Windows PowerShell cmdlet: `[Get-HotFix -Id kb3000850]`


During installation, the .Net Framework 4.6.1 is installed and might cause a reboot of the domain controller.


> [!NOTE]
> A minimum of 5 GB of space is required and 10 GB is recommended. This includes space needed for the ATP binaries, [ATP logs, and [performance logs](troubleshooting-ata-using-perf-counters.md).

### Server specifications

The ATP Lightweight Gateway requires a minimum of 2 cores and 6 GB of RAM installed on the domain controller.
For optimal performance, set the **Power Option** of the ATP Lightweight Gateway to **High Performance**.
The ATP Lightweight Gateway can be deployed on domain controllers of various loads and sizes, depending on the amount of network traffic to and from the domain controllers and the amount of resources installed on that domain controller.

>[!NOTE] 
> When running as a virtual machine dynamic memory or any other memory ballooning feature is not supported.

For more information about the ATP Lightweight Gateway hardware requirements, see [ATP capacity planning](ata-capacity-planning.md).

### Time synchronization

The ATP Center server, the ATP Lightweight Gateway servers, and the domain controllers must have time synchronized to within five minutes of each other.

### Network adapters

The ATP Lightweight Gateway monitors the local traffic on all of the domain controller's network adapters. <br>
After deployment, you can use the ATP Console if you ever want to modify which network adapters are monitored.

The Lightweight Gateway is not supported on domain controllers running Windows 2008 R2 with Broadcom Network Adapter Teaming enabled.

### Ports
The following table lists the minimum ports that the ATP Lightweight Gateway requires:

|Protocol|Transport|Port|To/From|Direction|
|------------|-------------|--------|-----------|-------------|
|DNS|TCP and UDP|53|DNS Servers|Outbound|
|NTLM over RPC|TCP|135|All devices on the network|Outbound|
|NetBIOS|UDP|137|All devices on the network|Outbound|
|SSL|TCP|443|ATP Center|Outbound|
|Syslog (optional)|UDP|514|SIEM Server|Inbound|

> [!NOTE]
> As part of the resolution process performed by the ATP Lightweight Gateway, the following ports need to be open inbound on devices on the network from the ATP Lightweight Gateways.
>
> -   NTLM over RPC
> -   NetBIOS

## ATP Console
Access to the ATP Console is via a browser, supporting the  browsers and settings:

-   Internet Explorer version 10 and above

-   Microsoft Edge

-   Google Chrome 40 and above

-   Minimum screen width resolution of 1700 pixels

## Related Videos
- [Choosing the right ATP Gateway type](https://channel9.msdn.com/Shows/Microsoft-Security/ATP-Deployment-Choose-the-Right-Gateway-Type)


## See Also
- [ATP sizing tool](http://aka.ms/atasizingtool)
- [ATP architecture](ata-architecture.md)
- [Install ATP](install-ata-step1.md)
- [Check out the ATP forum!](https://social.technet.microsoft.com/Forums/security/home?forum=mata)


