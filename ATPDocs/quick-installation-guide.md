---
title: Quick installation guide | Microsoft Defender for Identity.
description: Learn how to quickly install Microsoft Defender for Identity.
ms.date: 06/11/2023
ms.topic: how-to
---

# Quick installation guide

This article outlines the steps to install Microsoft Defender for Identity on Active Directory or Active Directory Federation Services (AD FS) servers.

> [!VIDEO https://www.microsoft.com/en-us/videoplayer/embed/RW16oLB]

In this short video, we show a step-by-step guide on how to install the Microsoft Defender for Identity sensor. The video begins by explaining the importance of having the sensors installed to protect your organization against identity-based attacks. It then goes on to show the user how to download and install the sensor, as well as how to find the potential health issues, and how to see your secure score Identity related posture assessments.


## Prerequisites

### Licensing requirements

Acquire a license for Enterprise Mobility + Security E5 (EMS E5/A5), Microsoft 365 E5 (M365 E5/A5/G5) or Microsoft 365 E5/A5/G5 Security directly via the [Microsoft 365 portal](https://www.microsoft.com/cloud-platform/enterprise-mobility-security-pricing) or use the Cloud Solution Partner (CSP) licensing model. 

Standalone Defender for Identity licenses are also available. 

For more information, see [Licensing and privacy](/defender-for-identity/technical-faq#licensing-and-privacy).

### Required permissions

- To create your Defender for Identity instance, you'll need an Azure AD tenant with at least one global/security administrator. Each Defender for Identity instance supports a multiple Active Directory forest boundary and Forest Functional Level (FFL) of Windows 2003 and above.

- You need to be a [global administrator or security administrator on the tenant](/azure/active-directory/users-groups-roles/directory-assign-admin-roles#available-roles) to access the Identity section on the Microsoft 365 Defender portal and be able to create the workspace.

For more information, see [Role groups](role-groups.md).

### Minimum system requirements

The Defender for Identity sensor supports installation on the different operating system versions, as described in the following table. It requires a minimum of 2 cores, 6 GB of RAM, and 6 GB of disk space installed on the domain controller.

For accurate calculations of the resources required by your server according to your specific load, refer to [Plan capacity for Microsoft Defender for Identity deployment](capacity-planning.md).

| **Operating system version** | **Server with Desktop**  **Experience** | **Server**  **Core** | **Nano**  **Server** | **Supported**  **installations** |
| ---------------------------- | --------------------------------------- | -------------------- | -------------------- | -------------------------------- |
| Windows Server  2012*        | ✔                                       | ✔                    | Not  applicable      | Domain  controller               |
| Windows Server  2012 R2*     | ✔                                       | ✔                    | Not  applicable      | Domain  controller               |
| Windows Server  2016         | ✔                                       | ✔                    | ❌                    | Domain controller,  AD FS, AD CS|
| Windows Server  2019**       | ✔                                       | ✔                    | ❌                    | Domain controller,  AD FS, AD CS|
| Windows Server  2022         | ✔                                       | ✔                    | ❌                    | Domain controller,  AD FS, AD CS|

\* Windows Server 2012 and Windows Server 2012 R2 will reach extended end of support on October 10, 2023. You should plan to upgrade those servers as Microsoft will no longer support the Defender for Identity sensor on devices running Windows Server 2012 and Windows Server 2012 R2.

\*\* Requires [KB4487044](https://support.microsoft.com/topic/february-12-2019-kb4487044-os-build-17763-316-6502eb5d-dde8-6902-e149-27ef359ed616) or a newer cumulative update. Sensors installed on Server 2019 without this update will be automatically stopped if the file version of the *ntdsai.dll* file in the system directory is older than *10.0.17763.316*.


## Install Defender for Identity

Make sure to install Defender for Identity on Windows 2012 and higher on a server with minimum of 2 cores, 6 GB of RAM, and 6 GB of disk space. For more information, see [Minimum system requirements](#minimum-system-requirements).

1. Download the Defender for Identity sensor from the [Microsoft 365 Defender portal](https://security.microsoft.com) in the **Settings** -> **Identities** -> **Sensors** page.

    - Copy the **Access key**. You'll need it for the installation.
    - You only need to download the installer once, as it can be used for every server in the tenant.

1. Verify that the servers you intend to install Defender for Identity sensors on can reach the Defender for Identity cloud service,  by accessing `https://*your-instance-name*sensorapi.atp.azure.com`.

    - To get your instance name, see the [About page](https://security.microsoft.com/settings/identities) in the portal.
    - For proxy configuration, see [Configure proxy settings for your sensor](configure-proxy.md).

1. From the domain controller, run the installer downloaded in step 1 and follow the instructions on the screen.  

    - For deployment on multiple domain controllers, use the silent installation.

### Notes

- For optimal performance, set the **Power Option** of the machine running the Defender for Identity sensor to **High Performance**.
- The domain controller can be a read-only domain controller (RODC).
- If you're installing on an AD FS farm, we recommend installing the sensor on each AD FS server, or at least on the primary node.
- During installation, if .NET Framework 4.7 or later isn't installed, the .NET Framework 4.7 will be installed and might require a reboot of the server. A reboot might also be required if there's a restart already pending. So when installing the sensors, consider scheduling a maintenance window for the domain controllers.
- For Windows Server 2012, the Defender for Identity sensor isn't supported in [Multiple Processor Group mode](/windows/win32/procthread/processor-groups). For more information about multi-processor group mode, see the [troubleshooting article](troubleshooting-known-issues.md#multi-processor-group-mode).
- When running as a virtual machine, all memory is required to be allocated to the virtual machine at all times.

## See also

For more detailed installation instructions, see the links in [Deploy Microsoft Defender for Identity with Microsoft 365 Defender](deploy-defender-identity.md).

