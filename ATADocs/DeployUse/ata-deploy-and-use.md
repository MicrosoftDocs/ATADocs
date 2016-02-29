---
title: Deploy and use Advanced Threat Analytics
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
# Pre-Installation Steps
This article describes the requirements for a successful deployment of ATA in your environment.

ATA is comprised of two components, the ATA Center and the ATA Gateway. For more information about the ATA components, see [ATA architecture](/understand/ata-architecture.md).

[Before you start](#ATAbeforeyoustart): This section lists information you should gather and accounts and network entities you should have before starting ATA installation.

[ATA Center](#ATAcenter): This section lists ATA Center hardware, software requirements as well as settings  you need to configure on your ATA Center server.

[ATA Gateway](#ATAgateway): This section lists ATA Gateway hardware, software requirements as well as settings  you need to configure on your ATA Gateway servers.

[ATA Console](#ATAconsole): This section lists browser requirements for running the ATA Console.

![](../Image/ATA-architecture-topology.jpg)

## <a name="ATAbeforeyoustart"></a>Before you start
This section lists information you should gather and accounts and network entities you should have before starting ATA installation.

-   **Domain controllers** running on Windows Server 2008 and later.

-   **User account and password** with read access to **all objects** in the domains that will be monitored.

    > [!NOTE]
    > If you have set custom ACLs on various Organizational Units (OU) in your domain, make sure that the selected user has read permissions to those OUs.

    Optional: User should have read only permissions on the Deleted Objects container. This will allow ATA to detect bulk deletion of objects in the domain. For information about configuring read only permissions on the Deleted Objects container, see the **Changing permissions on a deleted object container** section in the [View or Set Permissions on a Directory Object](https://technet.microsoft.com/library/cc816824%28v=ws.10%29.aspx) topic.

-   Optional: A user account of a user who has no network activities. This account will be configured as the ATA Honeytoken user. To configure the Honeytoken user you will need the SID of the user account, not the username.

-   Optional: In addition to collecting and analyzing network traffic to and from the domain controllers, ATA can use Windows event 4776 to further enhance ATA Pass-the-Hash detection. This can be received from your SIEM or by  setting Windows Event Forwarding from your domain controller. Events collected provide ATA with additional information that is not available via the domain controller network traffic.

-   It may be useful for you to have a list of all subnets used on your network for VPN and Wi-Fi, which reassign IP addresses between devices within a very short period of time (seconds or minutes).  You will want to identify these short-term lease subnets so that ATA can reduce their cache lifetime to accommodate the fast re-assignment between devices. See [Install ATA](install-ata.md) for short-term lease subnet configuration.

## <a name="ATAcenter"></a>ATA Center requirements
This section lists the requirements for the ATA Center.

The ATA Center supports installation on a server running Windows Server 2012 R2. Run Windows Update and make sure all important updates are installed.
 The number of domain controllers you are monitoring and the load on each of the domain controllers dictates the hardware requirements.

Installation of the ATA Center as a virtual machine is supported. For more information see [Configure port mirroring](/plandesign/configure-port-mirroring.md).

If you run the ATA Center as a virtual machine, shut down the server before creating a new checkpoint to avoid potential database corruption.

> [!NOTE]
> The ATA Center can be installed on a server that is a member of a domain or workgroup.

**Minimum requirements**

-   CPU -  8 cores

-   Memory - 48 GB

-   Storage - 1000 GB per month to monitor 2 lightly loaded domain controllers

The ATA Center requires a minimum of 21 days of data for user behavioral analytics. For more information on hardware requirements, see [ATA capacity planning](/plandesign/ata-capacity-planning.md).

> [!NOTE]
> If you want to install ATA in a lab with a few VMs, it is recommended that you have at least 2 cores, 4 GB of RAM and 100GB of storage to allow you to interact with the ATA Console without support for production deployment.

### Time synchronization
The ATA Center server,  the ATA Gateway servers and the domain controllers must have time synchronized to within 5 minutes of each other.

### BIOS settings
The ATA database necessitates that you **disable** Non-uniform memory access (NUMA) in the BIOS. Your system may refer to NUMA as Node Interleaving, in which case you will have to **enable** Node Interleaving. See your BIOS documentation for more information.

### Network adapters
Requirements:

-   One network adapter

-   Two IP addresses

Communication between the ATA Center and the ATA Gateway is encrypted using SSL on port 443. Additionally, the ATA Console runs on IIS and is secured using SSL on port 443. **Two IP addresses** are recommended. The ATA Center service will bind port 443 to the first IP address and IIS will bind port 443 to the second IP address.

> [!NOTE]
> A single IP address with two different ports can be used, but two IP addresses are recommended.

## ATA Deployment Guide
To deploy ATA, follow these steps:

1.  Prepare your network and servers according to the guidelines in [ATA prerequisites](/plandesign/ata-prerequisites.md).

2.  Perform pre-installation steps: [Install ATA](install-ata.md)

    -   [Configure port mirroring](/plandesign/configure-port-mirroring.md)

    -   [Validate port mirroring](.plandesign/validate-port-mirroring.md)

    -   Optional: [Configure event collection](/plandesign/configure-event-collection.md)

3.  [Install ATA](install-ata.md)

## After you've installed

- [Make changes to your configuration](modifying-ata-configuration.md)

- [Define alerts to notify you when something happens](setting-ata-alerts.md)

- [Visit the ATA Health Center](ata-health-center.md)

- [Review a list of suspicious activities](working-with-suspicious-activities.md)

- [Manage your ATA database](ata-database-management.md)

- [Manage the ATA telemetry](manage-telemetry-settings.md)

## See Also
[For support, check out our forum!](https://social.technet.microsoft.com/Forums/security/en-US/home?forum=mata)
