---
title: include file
description: include file
author: batamig
ms.date: 09/26/2023
---

The following table lists installation support across several operating system versions:

| Operating system version | Server with Desktop Experience | Server Core | Nano Server | Supported installations|
| ------------------------ | ----------------------------- | ------------ | -------------- | ----------------------- |
| Windows Server  2016         | ✔         | ✔          | Not supported    | Domain controller,  AD FS, AD CS        |
| Windows Server  2019 [<sup>*3*</sup>](#kb)       | ✔          | ✔     | Not supported    | Domain controller,  AD FS, AD CS        |
| Windows Server  2022         | ✔       | ✔       | Not supported     | Domain controller,  AD FS, AD CS        |


<a name="kb"></a><sup>*</sup> Requires [KB4487044](https://support.microsoft.com/topic/february-12-2019-kb4487044-os-build-17763-316-6502eb5d-dde8-6902-e149-27ef359ed616) or a newer cumulative update. Sensors installed on Server 2019 without this update will be automatically stopped if the *ntdsai.dll* file version found in the system directory is older than *10.0.17763.316*.

> [!NOTE]
> Windows Server 2012 and Windows Server 2012 R2 reached extended end of support on October 10, 2023. We recommend that you plan to upgrade those servers as Microsoft will no longer support the Defender for Identity sensor on devices running Windows Server 2012 and Windows Server 2012 R2. Sensors running on these operating systems will continue to report to Defender for Identity and even receive the sensor updates, but some of the new functionalities will not be available as they might rely on operating system capabilities. 
