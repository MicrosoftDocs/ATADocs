---
title: Microsoft Defender for Identity prerequisites
description: Describes the requirements for a successful deployment of Microsoft Defender for Identity in your environment
ms.date: 02/17/2021
ms.topic: overview
---

# Microsoft Defender for Identity prerequisites

This article describes the requirements for a successful deployment of [!INCLUDE [Product long](includes/product-long.md)] in your environment.

>[!NOTE]
> For information on how to plan resources and capacity, see [[!INCLUDE [Product short](includes/product-short.md)] capacity planning](capacity-planning.md).

[!INCLUDE [Product short](includes/product-short.md)] is composed of the [!INCLUDE [Product short](includes/product-short.md)] cloud service, which consists of the [!INCLUDE [Product short](includes/product-short.md)] portal and the [!INCLUDE [Product short](includes/product-short.md)] sensor. For more information about each [!INCLUDE [Product short](includes/product-short.md)] component, see [[!INCLUDE [Product short](includes/product-short.md)] architecture](architecture.md).

[!INCLUDE [Product short](includes/product-short.md)] protects your on-premises Active Directory users and/or users synced to your Azure Active Directory. To protect an environment made up of only AAD users, see [AAD Identity Protection](/azure/active-directory/identity-protection/overview).

To create your [!INCLUDE [Product short](includes/product-short.md)] instance, you'll need an AAD tenant with at least one global/security administrator. Each [!INCLUDE [Product short](includes/product-short.md)] instance supports a multiple Active Directory forest boundary and Forest Functional Level (FFL) of Windows 2003 and above.

This prerequisite guide is divided into the following sections to ensure you have everything you need to successfully deploy [!INCLUDE [Product short](includes/product-short.md)].

[Before you start](#before-you-start): Lists information to gather and accounts and network entities you'll need to have before starting to install.

[[!INCLUDE [Product short](includes/product-short.md)] portal](#azure-atp-portal-requirements): Describes [!INCLUDE [Product short](includes/product-short.md)] portal browser requirements.

[[!INCLUDE [Product short](includes/product-short.md)] sensor](#azure-atp-sensor-requirements): Lists [!INCLUDE [Product short](includes/product-short.md)] sensor hardware, and software requirements.

[[!INCLUDE [Product short](includes/product-short.md)] standalone sensor](#azure-atp-standalone-sensor-requirements): The [!INCLUDE [Product short](includes/product-short.md)] Standalone Sensor is installed on a dedicated server and requires port mirroring to be configured on the domain controller to receive network traffic.

> [!NOTE]
> [!INCLUDE [Product short](includes/product-short.md)] standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the [!INCLUDE [Product short](includes/product-short.md)] sensor.

## Before you start

This section lists information you should gather as well as accounts and network entity information you should have before starting [!INCLUDE [Product short](includes/product-short.md)] installation.

- Acquire a license for Enterprise Mobility + Security E5 (EMS E5/A5), Microsoft 365 E5 (M365 E5/A5/G5) or Microsoft 365 E5/A5/G5 Security directly via the [Microsoft 365 portal](https://www.microsoft.com/cloud-platform/enterprise-mobility-security-pricing) or use the Cloud Solution Partner (CSP) licensing model. Standalone [!INCLUDE [Product short](includes/product-short.md)] licenses are also available.

- Verify that the servers you intend to install [!INCLUDE [Product short](includes/product-short.md)] sensors on are able to reach the [!INCLUDE [Product short](includes/product-short.md)] Cloud Service. They should be able to access https://*your-instance-name*sensorapi.atp.azure.com (port 443). For example, https://*contoso-corp*sensorapi.atp.azure.com.<br><br>
To get your instance name, see the About page in the Identities settings section at <https://security.microsoft.com/settings/identities>. The [!INCLUDE [Product short](includes/product-short.md)] sensor supports the use of a proxy. For more information on proxy configuration, see [Configuring a proxy for [!INCLUDE [Product short](includes/product-short.md)]](configure-proxy.md).

- At least one directory services account with read access to all objects in the monitored domains. For instructions on how to create the directory service account, see [Directory Service Account recommendations](directory-service-accounts.md).

- If you run Wireshark on [!INCLUDE [Product short](includes/product-short.md)] standalone sensor, restart the [!INCLUDE [Product short](includes/product-short.md)] sensor service after you've stopped the Wireshark capture. If you don't restart the sensor service, the sensor stops capturing traffic.

- If you attempt to install the [!INCLUDE [Product short](includes/product-short.md)] sensor on a machine configured with a NIC Teaming adapter, you'll receive an installation error. If you want to install the [!INCLUDE [Product short](includes/product-short.md)] sensor on a machine configured with NIC teaming, see [[!INCLUDE [Product short](includes/product-short.md)] sensor NIC teaming issue](troubleshooting-known-issues.md#defender-for-identity-sensor-nic-teaming-issue).

- Optional **Honeytoken**: A user account of a user who has no network activities. This account is configured as a [!INCLUDE [Product short](includes/product-short.md)] Honeytoken user. For more information about using Honeytokens, see [Manage sensitive or honeytoken accounts](manage-sensitive-honeytoken-accounts.md).

- Optional: When deploying the standalone sensor, it's necessary to forward [Windows events](configure-windows-event-collection.md#configure-event-collection) to [!INCLUDE [Product short](includes/product-short.md)] to further enhance [!INCLUDE [Product short](includes/product-short.md)] authentication-based detections, additions to sensitive groups, and suspicious service creation detections.  [!INCLUDE [Product short](includes/product-short.md)] sensor receives these events automatically. In [!INCLUDE [Product short](includes/product-short.md)] standalone sensor, these events can be received from your SIEM or by setting Windows Event Forwarding from your domain controller. Events collected provide [!INCLUDE [Product short](includes/product-short.md)] with additional information that isn't available via the domain controller network traffic.

<a name="azure-atp-portal-requirements"></a>

## Defender for Identity portal requirements

Access to the [!INCLUDE [Product short](includes/product-short.md)] portal is via a browser, supporting the following browsers and settings:

- A browser that supports TLS 1.2, such as:
  - Microsoft Edge
  - Internet Explorer version 11 and above
  - Google Chrome 30.0 and above
- Minimum screen width resolution of 1700 pixels
- Firewall/proxy open - To communicate with the [!INCLUDE [Product short](includes/product-short.md)] cloud service, *.atp.azure.com port 443 must be open in your firewall/proxy. For more information about firewall/proxy configuration, see [Configure endpoint proxy and Internet connectivity settings for your Microsoft Defender for Identity Sensor](configure-proxy.md).

    > [!NOTE]
    > You can also use our Azure service tag (**AzureAdvancedThreatProtection**) to enable access to [!INCLUDE [Product short](includes/product-short.md)]. For more information about service tags, see [Virtual network service tags](/azure/virtual-network/service-tags-overview) or [download the service tags](https://www.microsoft.com/download/details.aspx?id=56519) file.

 ![[!INCLUDE [Product short.](includes/product-short.md)] architecture diagram](media/architecture-topology.png)

> [!NOTE]
> By default, [!INCLUDE [Product short](includes/product-short.md)] supports up to 350 sensors. If you want to install more sensors, contact [!INCLUDE [Product short](includes/product-short.md)] support.

## Defender for Identity Network Name Resolution (NNR) requirements

Network Name Resolution (NNR) is a main component of [!INCLUDE [Product short](includes/product-short.md)] functionality. To resolve IP addresses to computer names, [!INCLUDE [Product short](includes/product-short.md)] sensors look up the IP addresses using the following methods:

- NTLM over RPC (TCP Port 135)
- NetBIOS (UDP port 137)
- RDP (TCP port 3389) - only the first packet of **Client hello**
- Queries the DNS server using reverse DNS lookup of the IP address (UDP 53)

For the first three methods to work, the relevant ports must be opened inbound from the [!INCLUDE [Product short](includes/product-short.md)] sensors to devices on the network. To learn more about [!INCLUDE [Product short](includes/product-short.md)] and NNR, see [[!INCLUDE [Product short](includes/product-short.md)] NNR policy](nnr-policy.md).

For the best results, we recommend using all of the methods. If this isn't possible, you should use the DNS lookup method and at least one of the other methods.

<a name="azure-atp-sensor-requirements"></a>

## Defender for Identity sensor requirements

This section lists the requirements for the [!INCLUDE [Product short](includes/product-short.md)] sensor.

### General

The [!INCLUDE [Product short](includes/product-short.md)] sensor supports installation on domain controllers or Active Directory Federation Services (AD FS) servers, as shown in the following table.

| Operating system version   | Server with Desktop Experience | Server Core | Nano Server    | Supported installations  |
| -------------------------- | ------------------------------ | ----------- | -------------- | ------------------------ |
| Windows Server 2008 R2 SP1 | &#10004;                       | &#10060;    | Not applicable | Domain controller        |
| Windows Server 2012        | &#10004;                       | &#10004;    | Not applicable | Domain controller        |
| Windows Server 2012 R2     | &#10004;                       | &#10004;    | Not applicable | Domain controller        |
| Windows Server 2016        | &#10004;                       | &#10004;    | &#10060;       | Domain controller, AD FS |
| Windows Server 2019\*      | &#10004;                       | &#10004;    | &#10060;       | Domain controller, AD FS |

\* Requires [KB4487044](https://support.microsoft.com/help/4487044/windows-10-update-kb4487044) or newer cumulative update. Sensors installed on Server 2019 without this update will be automatically stopped if the file version of the *ntdsai.dll* file in the system directory is older than *10.0.17763.316*.

The domain controller can be a read-only domain controller (RODC).

For sensors running on domain controllers and AD FS to communicate with the cloud service, you must open port 443 in your firewalls and proxies to `*.atp.azure.com`. If you're installing on an AD FS farm, we recommend installing the sensor on each AD FS server, or at least on the primary node.

During installation, if .NET Framework 4.7 or later isn't installed, the .NET Framework 4.7 is installed and might require a reboot of the server. A reboot might also be required if there is a restart already pending.

> [!NOTE]
> A minimum of 6 GB of disk space is required and 10 GB is recommended. This includes space needed for the [!INCLUDE [Product short](includes/product-short.md)] binaries, [!INCLUDE [Product short](includes/product-short.md)] logs, and performance logs.

### Server specifications

The [!INCLUDE [Product short](includes/product-short.md)] sensor requires a minimum of 2 cores and 6 GB of RAM installed on the domain controller.
For optimal performance, set the **Power Option** of the machine running the [!INCLUDE [Product short](includes/product-short.md)] sensor to **High Performance**.

[!INCLUDE [Product short](includes/product-short.md)] sensors can be deployed on domain controller or AD FS servers of various loads and sizes, depending on the amount of network traffic to and from the servers, and the amount of resources installed.

For Windows Operating systems 2008R2 and 2012, the [!INCLUDE [Product short](includes/product-short.md)] sensor isn't supported in a [Multi Processor Group](/windows/win32/procthread/processor-groups) mode. For more information about multi-processor group mode, see [troubleshooting](troubleshooting-known-issues.md#multi-processor-group-mode).

>[!NOTE]
> When running as a virtual machine, all memory is required to be allocated to the virtual machine at all times.

For more information about the [!INCLUDE [Product short](includes/product-short.md)] sensor hardware requirements, see [[!INCLUDE [Product short](includes/product-short.md)] capacity planning](capacity-planning.md).

### Time synchronization

The servers and domain controllers onto which the sensor is installed must have time synchronized to within five minutes of each other.

### Network adapters

The [!INCLUDE [Product short](includes/product-short.md)] sensor monitors the local traffic on all of the domain controller's network adapters.  
After deployment, use the [!INCLUDE [Product short](includes/product-short.md)] portal to modify which network adapters are monitored.

The sensor isn't supported on domain controllers running Windows 2008 R2 with Broadcom Network Adapter Teaming enabled.

### Ports

The following table lists the minimum ports that the [!INCLUDE [Product short](includes/product-short.md)] sensor requires:

|Protocol|Transport|Port|From|To|
|------------|-------------|--------|-----------|---|
|**Internet ports**|||||
|SSL (\*.atp.azure.com)|TCP|443|[!INCLUDE [Product short](includes/product-short.md)] sensor|[!INCLUDE [Product short](includes/product-short.md)] cloud service|
|**Internal ports**|||||
|DNS|TCP and UDP|53|[!INCLUDE [Product short](includes/product-short.md)] sensor|DNS Servers|
|Netlogon (SMB, CIFS, SAM-R)|TCP/UDP|445|[!INCLUDE [Product short](includes/product-short.md)] sensor|All devices on network|
|RADIUS|UDP|1813|RADIUS|[!INCLUDE [Product short](includes/product-short.md)] sensor|
|**Localhost ports**\*|Required for Sensor Service updater||||
|SSL (localhost)|TCP|444|Sensor Service|Sensor Updater Service|
|**NNR ports**\*\*|||||
|NTLM over RPC|TCP|Port 135|[!INCLUDE [Product short](includes/product-short.md)]|All devices on network|
|NetBIOS|UDP|137|[!INCLUDE [Product short](includes/product-short.md)]|All devices on network|
|RDP|TCP|3389, only the first packet of Client hello|[!INCLUDE [Product short](includes/product-short.md)]|All devices on network|

\* By default, localhost to localhost traffic is allowed unless a custom firewall policy blocks it.  
\*\* One of these ports is required, but we recommend opening all of them.

### Windows Event logs

[!INCLUDE [Product short](includes/product-short.md)] detection relies on specific [Windows Event logs](configure-windows-event-collection.md#configure-event-collection) that the sensor parses from your domain controllers. For the correct events to be audited and included in the Windows Event log, your domain controllers require accurate Advanced Audit Policy settings. For more information about setting the correct policies, see, [Advanced audit policy check](configure-windows-event-collection.md). To [make sure Windows Event 8004 is audited](configure-windows-event-collection.md#configure-audit-policies) as needed by the service, review your [NTLM audit settings](/archive/blogs/askds/ntlm-blocking-and-you-application-analysis-and-auditing-methodologies-in-windows-7).

For sensors running on AD FS servers, configure the auditing level to **Verbose**. For information on how to configure the auditing level, see [Event auditing information for AD FS](/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-logging#event-auditing-information-for-ad-fs-on-windows-server-2016).

> [!NOTE]
> Using the Directory service user account, the sensor queries endpoints in your organization for local admins using SAM-R (network logon) in order to build the [lateral movement path graph](use-case-lateral-movement-path.md). For more information, see [Configure SAM-R required permissions](install-step8-samr.md).

<a name="azure-atp-standalone-sensor-requirements"></a>

## Defender for Identity standalone sensor requirements

This section lists the requirements for the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor.

> [!NOTE]
> [!INCLUDE [Product short](includes/product-short.md)] standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the [!INCLUDE [Product short](includes/product-short.md)] sensor.

### General

The [!INCLUDE [Product short](includes/product-short.md)] standalone sensor supports installation on a server running Windows Server 2012 R2, Windows Server 2016 and Windows Server 2019 (including Server Core).
The [!INCLUDE [Product short](includes/product-short.md)] standalone sensor can be installed on a server that is a member of a domain or workgroup.
The [!INCLUDE [Product short](includes/product-short.md)] standalone sensor can be used to monitor Domain Controllers with Domain Functional Level of Windows 2003 and above.

For your standalone sensor to communicate with the cloud service, port 443 in your firewalls and proxies to *.atp.azure.com must be open.

For information on using virtual machines with the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor, see [Configure port mirroring](configure-port-mirroring.md).

> [!NOTE]
> A minimum of 5 GB of disk space is required and 10 GB is recommended. This includes space needed for the [!INCLUDE [Product short](includes/product-short.md)] binaries, [!INCLUDE [Product short](includes/product-short.md)] logs, and performance logs.

### Server specifications

For optimal performance, set the **Power Option** of the machine running the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor to **High Performance**.

[!INCLUDE [Product short](includes/product-short.md)] standalone sensors can support monitoring multiple domain controllers, depending on the amount of network traffic to and from the domain controllers.

>[!NOTE]
> When running as a virtual machine, all memory is required to be allocated to the virtual machine at all times.

For more information about the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor hardware requirements, see [[!INCLUDE [Product short](includes/product-short.md)] capacity planning](capacity-planning.md).

### Time synchronization

The servers and domain controllers onto which the sensor is installed must have time synchronized to within five minutes of each other.

### Network adapters

The [!INCLUDE [Product short](includes/product-short.md)] standalone sensor requires at least one Management adapter and at least one Capture adapter:

- **Management adapter** - used for communications on your corporate network. The sensor will use this adapter to query the DC it's protecting and performing resolution to machine accounts.

    This adapter should be configured with the following settings:

    - Static IP address including default gateway

    - Preferred and alternate DNS servers

    - The **DNS suffix for this connection** should be the DNS name of the domain for each domain being monitored.

        ![Configure DNS suffix in advanced TCP/IP settings.](media/dns-suffix.png)

        > [!NOTE]
        > If the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor is a member of the domain, this may be configured automatically.

- **Capture adapter** - used to capture traffic to and from the domain controllers.

    > [!IMPORTANT]
    >
    > - Configure port mirroring for the capture adapter as the destination of the domain controller network traffic. For more information, see [Configure port mirroring](configure-port-mirroring.md). Typically, you need to work with the networking or virtualization team to configure port mirroring.
    > - Configure a static non-routable IP address (with /32 mask) for your environment with no default sensor gateway and no DNS server addresses. For example, 10.10.0.10/32. This ensures that the capture network adapter can capture the maximum amount of traffic and that the management network adapter is used to send and receive the required network traffic.

### Ports

The following table lists the minimum ports that the [!INCLUDE [Product short](includes/product-short.md)] standalone sensor requires configured on the management adapter:

|Protocol|Transport|Port|From|To|
|------------|-------------|--------|-----------|---|
|**Internet ports**||||
|SSL (\*.atp.azure.com)|TCP|443|[!INCLUDE [Product short](includes/product-short.md)] Sensor|[!INCLUDE [Product short](includes/product-short.md)] cloud service|
|**Internal ports**||||
|LDAP|TCP and UDP|389|[!INCLUDE [Product short](includes/product-short.md)] Sensor|Domain controllers|
|Secure LDAP (LDAPS)|TCP|636|[!INCLUDE [Product short](includes/product-short.md)] Sensor|Domain controllers|
|LDAP to Global Catalog|TCP|3268|[!INCLUDE [Product short](includes/product-short.md)] Sensor|Domain controllers|
|LDAPS to Global Catalog|TCP|3269|[!INCLUDE [Product short](includes/product-short.md)] Sensor|Domain controllers|
|Kerberos|TCP and UDP|88|[!INCLUDE [Product short](includes/product-short.md)] Sensor|Domain controllers|
|Netlogon (SMB, CIFS, SAM-R)|TCP and UDP|445|[!INCLUDE [Product short](includes/product-short.md)] Sensor|All devices on network|
|Windows Time|UDP|123|[!INCLUDE [Product short](includes/product-short.md)] Sensor|Domain controllers|
|DNS|TCP and UDP|53|[!INCLUDE [Product short](includes/product-short.md)] Sensor|DNS Servers|
|Syslog (optional)|TCP/UDP|514, depending on configuration|SIEM Server|[!INCLUDE [Product short](includes/product-short.md)] Sensor|
|RADIUS|UDP|1813|RADIUS|[!INCLUDE [Product short](includes/product-short.md)] sensor|
|**Localhost ports**\*|Required for Sensor Service updater||||
|SSL (localhost)|TCP|444|Sensor Service|Sensor Updater Service|
|**NNR ports**\*\*|||||
|NTLM over RPC|TCP|135|[!INCLUDE [Product short](includes/product-short.md)]|All devices on network|
|NetBIOS|UDP|137|[!INCLUDE [Product short](includes/product-short.md)]|All devices on network|
|RDP|TCP|3389, only the first packet of Client hello|[!INCLUDE [Product short](includes/product-short.md)]|All devices on network|

\* By default, localhost to localhost traffic is allowed unless a custom firewall policy blocks it.  
\*\* One of these ports is required, but we recommend opening all of them.

> [!NOTE]
>
> - Using the Directory service user account, the sensor queries endpoints in your organization for local admins using SAM-R (network logon) in order to build the [lateral movement path graph](use-case-lateral-movement-path.md). For more information, see [Configure SAM-R required permissions](install-step8-samr.md).

## See Also

- [[!INCLUDE [Product short](includes/product-short.md)] sizing tool](<https://aka.ms/aatpsizingtool>)
- [[!INCLUDE [Product short](includes/product-short.md)] architecture](architecture.md)
- [Install [!INCLUDE [Product short](includes/product-short.md)]](install-step1.md)
- [Network Name Resolution (NNR)](nnr-policy.md)
- [Check out the [!INCLUDE [Product short](includes/product-short.md)] forum!](<https://aka.ms/MDIcommunity>)
