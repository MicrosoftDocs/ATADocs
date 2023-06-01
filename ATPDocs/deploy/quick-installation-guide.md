---
title: Quick installation guide | Microsoft Defender for Identity
description: Learn how to quickly install Microsoft Defender for Identity.
ms.date: 05/30/2023
ms.topic: quickstart
---

# Quick installation guide

This article outlines the high level steps required to install Microsoft Defender for Identity on Active Directory or Active Directory Federation Services (AD FS) servers.

Use the other articles in the **Deploy** section of the documentation to take you through a full, step-by-step deployment.

## Prerequisites

| Prerequisite / Recommendation |Description  |
|---------|---------|
|**Specifications**     |  Make sure to install Defender for Identity on Windows version 2012 or higher, on a domain controller server with a minimum of:<br><br>- 2 cores<br>- 6 GB of RAM<br>- 6 GB of disk space  <br><br>Defender for Identity supports read-only domain controllers (RODC).     |
|**Performance**   | For optimal performance, set the **Power Option** of the machine running the Defender for Identity sensor to **High Performance**.        |
|**Maintenance window**     |   We recommend scheduling a maintenance window for your domain controllers, as a restart might be required if the installation runs and a restart is already pending, or if .NET Framework needs to be installed. <br><br>If .NET Framework version 4.7 or later isn't already found on the system, .NET Framework version 4.7 is installed, and may require a restart.      |

For more information, see:

- [Minimum system requirements](#minimum-system-requirements)
- [Plan capacity for Microsoft Defender for Identity deployment](capacity-planning.md).

## Install the Defender for Identity sensor

1. Download the Defender for Identity sensor from the [Microsoft 365 Defender portal](https://security.microsoft.com) in the **Settings** -> **Identities** -> **Sensors** page. Select **Add sensor > Download installer**.

    You'll only need to do this step once, and then use the same installer on each Active Directory instance. If you're installing on an AD FS farm, we recommend installing the sensor on each AD FS server, or at least on the primary node.

1. From each server where you intend to install a Defender for Identity sensor, try accessing `https://<your-instance-name>sensorapi.atp.azure.com ` on port 443. Successful access verifies that the server can reach the Defender for Identity cloud service.

    To get your instance name, see the Microsoft 365 Defender **Settings > Identities > [About](https://security.microsoft.com/settings/identities)** page.

    For more information, see also [Configure proxy settings for your sensor](configure-proxy.md).

1. From the domain controller server, run the downloaded sensor installation file and follow the instructions on the screen.  Use the silent installation to install the sensor on multiple domain controllers.

## Minimum system requirements
 <!--make these into include files-->
The following table lists installation support across several operating system versions:

| Operating system version | Server with Desktop Experience | Server Core | Nano Server | Supported installations|
| ------------------------ | ----------------------------- | ------------ | -------------- | ----------------------- |
| Windows Server  2012 [<sup>1</sup>](#eos) [<sup>2</sup></sup>](#mpg)        | ✔     | ✔    | Not  applicable    | Domain  controller       |
| Windows Server  2012 R2 [<sup>1</sup>](#eos)     | ✔   | ✔                    | Not  applicable      | Domain  controller               |
| Windows Server  2016         | ✔         | ✔          | Not supported    | Domain controller,  AD FS        |
| Windows Server  2019 [<sup>3</sup>](#kb)       | ✔          | ✔     | Not supported    | Domain controller,  AD FS        |
| Windows Server  2022         | ✔       | ✔       | Not supported     | Domain controller,  AD FS        |

> [!IMPORTANT]
> When running as a virtual machine, all memory must be allocated to the virtual machine at all times.

<a name="eos"></a><sup>1</sup> Windows Server 2012 and Windows Server 2012 R2 will reach extended end of support on **October 10, 2023**. We recommend that you plan to upgrade those servers by that point, as Microsoft will no longer support the Defender for Identity sensor on devices running Windows Server 2012 and Windows Server 2012 R2.

<a name="mpg"></a><sup>2</sup> For Windows Server 2012, the Defender for Identity sensor isn't supported in a [Multi Processor Group mode](/windows/win32/procthread/processor-groups). For more information, see [Multi Processor Group mode troubleshooting](../troubleshooting-known-issues.md#multi-processor-group-mode).

<a name="kb"></a><sup>3</sup> Requires [KB4487044](https://support.microsoft.com/topic/february-12-2019-kb4487044-os-build-17763-316-6502eb5d-dde8-6902-e149-27ef359ed616) or a newer cumulative update. Sensors installed on Server 2019 without this update will be automatically stopped if the *ntdsai.dll* file version found in the system directory is older than *10.0.17763.316*.

## Next steps

For a full Defender for Identity deployment, start learning about full deployment prerequisites. 

For more information, see [Microsoft Defender for Identity prerequisites](prerequisites.md).
