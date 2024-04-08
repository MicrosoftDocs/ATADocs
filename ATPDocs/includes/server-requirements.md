---
title: include file
description: include file
ms.topic: include
ms.date: 09/26/2023
---

Defender for Identity sensors can be installed on the following operating systems:

### [Defender for Identity sensor](#mdi-sensor)

- **Windows Server 2016**
- **Windows Server 2019**. Requires [KB4487044](https://support.microsoft.com/topic/february-12-2019-kb4487044-os-build-17763-316-6502eb5d-dde8-6902-e149-27ef359ed616) or a newer cumulative update. Sensors installed on Server 2019 without this update will be automatically stopped if the *ntdsai.dll* file version found in the system directory is older than *10.0.17763.316*
- **Windows Server 2022**

For all operating systems:

- Both servers with desktop experience and server cores are supported.
- Nano servers are not supported.
- Installations are supported for domain controllers, AD FS, and AD CS servers.

### [Unified sensor](#unified-sensor)

If you're using a unified Microsoft Defender for Endpoint and Defender for Identity sensor, supported operating systems include:

- Windows Server 2019
- Window Server 2022
- [Patch level March 2024 Cumulative Update](https://support.microsoft.com/topic/march-12-2024-kb5035857-os-build-20348-2340-a7953024-bae2-4b1a-8fc1-74a17c68203c)

> [!IMPORTANT]
> After installing Patch level March 2024 Cumulative Update, LSASS might experience a memory leak on domain controllers when on-premises and cloud-based Active Directory Domain Controllers service Kerberos authentication requests.
>
> This issue is addressed in the out-of-band update KB5037422.

---