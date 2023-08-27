---
title: Prerequisites | Microsoft Defender for Identity
description: Learn about the requirements for a successful Microsoft Defender for Identity deployment.
ms.date: 05/31/2023
ms.topic: conceptual
---

# Microsoft Defender for Identity prerequisites

This article describes the requirements for a successful Microsoft Defender for Identity deployment. For more information, see [Defender for Identity architecture](../architecture.md).

<!--are we missing details about service BGP community from the original file?-->
## Licensing requirements

Before deploying Defender for Identity, make sure to acquire one of the following Microsoft 365 licenses:


- Enterprise Mobility + Security E5 (EMS E5/A5)
- Microsoft 365 E5 (M365 E5/A5/G5)
- Microsoft 365 E5/A5/G5 Security

Defender for Identity also supports standalone licenses.

Acquire your licenses directly via the [Microsoft 365 portal](https://www.microsoft.com/cloud-platform/enterprise-mobility-security-pricing) or use the Cloud Solution Partner (CSP) licensing model.


For more information, see [Licensing and privacy](/defender-for-identity/technical-faq#licensing-and-privacy).

## Required permissions

To create your Defender for Identity instance, you'll need an Azure Active Directory (Azure AD) tenant with at least one Global or Security administrator.

Each Defender for Identity instance supports  multiple Active Directory forest boundaries and Forest Functional Levels (FFL), for Windows 2003 and higher.

You'll need Global or Security administrator access on your tenant to access the **Identity** section of the Microsoft 365 Defender **Settings** area and create the workspace.

For more information, see [Microsoft Defender for Identity role groups](role-groups.md).

## Defender for Identity firewall requirements

Download the [Azure IP Ranges and Service Tags – Public Cloud](https://www.microsoft.com/download/details.aspx?id=56519) file and use the **AzureAdvancedThreatProtection** service tag to help you enable access to Defender for Identity.

For more information, see [Virtual network service tags](/azure/virtual-network/service-tags-overview).

## Required network adapters

The Defender for Identity sensor monitors local traffic on all of the domain controller's network adapters. After deployment, you'll use the Microsoft 365 Defender portal to modify which network adapters are monitored.

If you install the Defender for Identity sensor on a machine configured with a NIC teaming adapter and the Winpcap driver, you'll receive an installation error.

To install the Defender for Identity sensor on a machine configured with NIC teaming, make sure you replace the Winpcap driver with Npcap. For more information, see [How do I download and install or upgrade the Npcap driver?](../technical-faq.yml#how-do-i-download-and-install-or-upgrade-the-npcap-driver)

## Sensor requirements

The following table summarizes requirements for the domain controller server where you'll install the Defender for Identity sensor.

| Prerequisite / Recommendation |Description  |
|---------|---------|
|**Specifications**     |  Make sure to install Defender for Identity on Windows version 2012 or higher, on a domain controller server with a minimum of:<br><br>- 2 cores<br>- 6 GB of RAM<br>- 6 GB of disk space required, 10 GB recommended, including space for Defender for Identity binaries and logs <br><br>Defender for Identity supports read-only domain controllers (RODC).     |
|**Performance**   | For optimal performance, set the **Power Option** of the machine running the Defender for Identity sensor to **High Performance**.        |
|**Maintenance window**     |   We recommend scheduling a maintenance window for your domain controllers, as a restart might be required if the installation runs and a restart is already pending, or if .NET Framework needs to be installed. <br><br>If .NET Framework version 4.7 or later isn't already found on the system, .NET Framework version 4.7 is installed, and may require a restart.      |

### Minimum operating system requirements

The following table lists installation support across several operating system versions:

| Operating system version | Server with Desktop Experience | Server Core | Nano Server | Supported installations|
| ------------------------ | ----------------------------- | ------------ | -------------- | ----------------------- |
| Windows Server  2012 [<sup>1</sup>](#eos) [<sup>2</sup></sup>](#mpg)        | ✔     | ✔    | Not  applicable    | Domain  controller       |
| Windows Server  2012 R2 [<sup>1</sup>](#eos)     | ✔   | ✔       | Not  applicable      | Domain  controller  |
| Windows Server  2016         | ✔         | ✔          | Not supported    | Domain controller,  AD FS        |
| Windows Server  2019 [<sup>3</sup>](#kb)       | ✔          | ✔     | Not supported    | Domain controller,  AD FS        |
| Windows Server  2022         | ✔       | ✔       | Not supported     | Domain controller,  AD FS        |

<a name="eos"></a><sup>1</sup> Windows Server 2012 and Windows Server 2012 R2 will reach extended end of support on **October 10, 2023**. We recommend that you plan to upgrade those servers by that point, as Microsoft will no longer support the Defender for Identity sensor on devices running Windows Server 2012 and Windows Server 2012 R2.

<a name="mpg"></a><sup>2</sup> For Windows Server 2012, the Defender for Identity sensor isn't supported in a [Multi Processor Group mode](/windows/win32/procthread/processor-groups). For more information, see [Multi Processor Group mode troubleshooting](../troubleshooting-known-issues.md#multi-processor-group-mode).

<a name="kb"></a><sup>3</sup> Requires [KB4487044](https://support.microsoft.com/topic/february-12-2019-kb4487044-os-build-17763-316-6502eb5d-dde8-6902-e149-27ef359ed616) or a newer cumulative update. Sensors installed on Server 2019 without this update will be automatically stopped if the *ntdsai.dll* file version found in the system directory is older than *10.0.17763.316*.

### Required ports

|**Protocol**   |**Transport**         |**Port**         |**From**       |**To**   |
|------------|---------|---------|-------|--------------|
|**Internet ports**          | | | | |
|**SSL** (\*.atp.azure.com)     |TCP      |443 |Defender for Identity sensor|Defender for Identity cloud service|
|**Internal ports**          | | | | |
|**DNS**            |TCP and UDP           |53  |Defender for Identity sensor|DNS Servers           |
|**Netlogon**  <br>(SMB, CIFS, SAM-R)|TCP/UDP  |445 |Defender for Identity sensor|All devices on the network|
|**RADIUS**         |UDP      |1813|RADIUS         |Defender for
Identity sensor      |
|**Localhost ports** [<sup>1</sup>](#localhost) <br><br>Required for the sensor service updater      ||    |  |         |
|**SSL** (localhost)|TCP      |444 |Sensor service|Sensor updater service            |
|**NNR ports** [<sup>2</sup>](#nnr)       | | | | |
|**NTLM over RPC**  |TCP      |Port 135         |Defender for Identity sensor|All devices on network|
|**NetBIOS**        |UDP      |137 |Defender for Identity sensor|All devices on network|
|**RDP**            |TCP      |3389, only the first packet of Client hello|Defender for Identity sensor|All devices on network|

<a name=localhost></a><sup>1</sup> By default, localhost to localhost traffic is allowed unless a custom firewall policy blocks it. 

<a name=nnr></a><sup>2</sup> While only one of the listed ports is required, we recommend opening all of them.

### Dynamic memory requirements

The following table describes memory requirements on the server used for the Defender for Identity sensor, depending on the type of virtualization you're using:

|VM running on|Description|
|------------|-------------|
|**Hyper-V**|Ensure that **Enable Dynamic Memory** isn't enabled for the VM.|
|**VMware**|Ensure that the amount of memory configured and the reserved memory are the same, or select the **Reserve all guest memory (All locked)** option in the VM settings.|
|**Other virtualization host**|Refer to the vendor supplied documentation on how to ensure that memory is fully allocated to the VM at all times. |

> [!IMPORTANT]
> When running as a virtual machine, all memory must be allocated to the virtual machine at all times.


## Next steps

> [!div class="step-by-step"]
> [Plan capacity for Microsoft Defender for Identity »](capacity-planning.md)
