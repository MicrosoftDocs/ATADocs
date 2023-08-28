---
title: Quick installation guide | Microsoft Defender for Identity
description: Learn how to quickly install Microsoft Defender for Identity on Active Directory or Active Directory Federation Services (AD FS) servers.
ms.date: 08/27/2023
ms.topic: how-to
---

# Quick installation guide

This article outlines the steps required when installing Microsoft Defender for Identity sensors on Active Directory or Active Directory Federation Services (AD FS) servers. For more detailed instructions, see [Deploy Microsoft Defender for Identity with Microsoft 365 Defender](deploy-defender-identity.md).

Watch the following video for a step-by-step demo. Learn about:

- The importance of installing Defender for Identity sensors to protect your organization against identity-based attacks
- Downloading and installing the sensor
- Finding potential health issues
- Viewing identity-related posture assessments in Microsoft Secure Score

> [!VIDEO https://www.microsoft.com/en-us/videoplayer/embed/RW16oLB]

## Prerequisites

This section lists the prerequisites required before installing the Defender for Identity sensor, including:

- Licensing
- Permissions
- System requirements
- Recommendations for performance and maintenance windows

### Licensing requirements

Make sure that you have one of the following licenses:

- Enterprise Mobility + Security E5 (EMS E5/A5)
- Microsoft 365 E5 (M365 E5/A5/G5)
- Microsoft 365 E5/A5/G5 Security
- A standalone Defender for Identity licenses

Acquire licenses directly via the [Microsoft 365 portal](https://www.microsoft.com/cloud-platform/enterprise-mobility-security-pricing) or use the Cloud Solution Partner (CSP) licensing model. For more information, see [Licensing and privacy](/defender-for-identity/technical-faq#licensing-and-privacy).

### Required permissions

- To create your Defender for Identity instance, you'll need an Azure AD tenant with at least one global/security administrator. Each Defender for Identity instance supports a multiple Active Directory forest boundary and Forest Functional Level (FFL) of Windows 2003 and above.

- You need to be a [global administrator or security administrator on the tenant](/azure/active-directory/users-groups-roles/directory-assign-admin-roles#available-roles) to access the Identity section on the Microsoft 365 Defender portal and be able to create the workspace.

For more information, see [Role groups](role-groups.md).

### Minimum system requirements

The Defender for Identity sensor supports installation on the different operating system versions, as described in the following table. It requires a minimum of 2 cores, 6 GB of RAM, and 6 GB of disk space installed on the domain controller.

For more information, see [Plan capacity for Microsoft Defender for Identity deployment](capacity-planning.md).

| **Operating system version** | **Server with Desktop**  **Experience** | **Server**  **Core** | **Nano**  **Server** | **Supported**  **installations** |
| ---------------------------- | --------------------------------------- | -------------------- | -------------------- | -------------------------------- |
| Windows Server  2012 [*](#win2012)        | ✔                                       | ✔                    | Not  applicable      | Domain  controller               |
| Windows Server  2012 R2 [*](#win2012)     | ✔                                       | ✔                    | Not  applicable      | Domain  controller               |
| Windows Server  2016         | ✔                                       | ✔                    | ❌                    | Domain controller,  AD FS, AD CS|
| Windows Server  2019 [**](#win2019)       | ✔                                       | ✔                    | ❌                    | Domain controller,  AD FS, AD CS|
| Windows Server  2022         | ✔                                       | ✔                    | ❌                    | Domain controller,  AD FS, AD CS|

> [!NOTE]
> When running as a virtual machine, all memory is required to be allocated to the virtual machine at all times.
>

<a name="win2012"></a>* Windows Server 2012 and Windows Server 2012 R2 will reach extended end of support on October 10, 2023. We recommend that you plan to upgrade those servers, as Microsoft will no longer support the Defender for Identity sensor on devices running Windows Server 2012 and Windows Server 2012 R2. 

Also, for Windows Server 2012, the Defender for Identity sensor isn't supported in [Multiple Processor Group mode](/windows/win32/procthread/processor-groups). For more information, see [troubleshooting for Multi Processor Group mode](../troubleshooting-known-issues.md#multi-processor-group-mode).

<a name="win2019"></a>** Requires [KB4487044](https://support.microsoft.com/topic/february-12-2019-kb4487044-os-build-17763-316-6502eb5d-dde8-6902-e149-27ef359ed616) or a newer cumulative update. Sensors installed on Server 2019 without this update are automatically stopped if the file version of the *ntdsai.dll* file in the system directory is older than *10.0.17763.316*.

### Performance recommendations

For optimal performance, set the **Power Option** of the machine running the Defender for Identity sensor to **High Performance**.

### Schedule a maintenance window (optional)

During installation, if .NET Framework 4.7 or later isn't installed, the .NET Framework 4.7 will be installed and might require a reboot of the server. A reboot might also be required if there's a restart already pending. 

When installing your sensors, consider scheduling a maintenance window for your domain controllers.

## Install Defender for Identity

This procedure describes how to install the Defender for Identity sensor on a Windows server version 2012 or higher. Make sure that your server has the [minium system requirements](#minimum-system-requirements).

> [!NOTE]
> Defender for Identity sensors can be installed on read-only domain controllers (RODC). If you're installing on an AD FS farm, we recommend installing the sensor on each AD FS server, or at least on the primary node.
>

**To download and install the sensor**:

1. Download the Defender for Identity sensor from the [Microsoft 365 Defender portal](https://security.microsoft.com). Select **Settings** -> **Identities** -> **Sensors** -> **Add sensor** and copy the **Access key** value, which you'll need for the installation.

    You only need to download the installer once, as it can be used for every server in the tenant. Make sure that no pop-up blocker is blocking the download.

1. Verify that the servers you intend to install Defender for Identity sensors on can reach the Defender for Identity cloud service. From each server, try accessing: `https://*your-instance-name*sensorapi.atp.azure.com`.

    - To get your instance name, see the [About page](https://security.microsoft.com/settings/identities) in the portal.
    - For proxy configuration, see [Configure proxy settings for your sensor](configure-proxy.md).

1. From the domain controller, run the installer you'd downloaded from Microsoft 365 Defender and follow the instructions on the screen.  

    For deployment on multiple domain controllers, use the silent installation.

## Next step

For more detailed installation instructions, see the links in [Deploy Microsoft Defender for Identity with Microsoft 365 Defender](deploy-defender-identity.md).
