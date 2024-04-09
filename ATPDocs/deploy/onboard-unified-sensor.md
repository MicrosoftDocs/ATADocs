---
title: Onboard a unified sensor | Microsoft Defender for Identity
description: Learn how to deploy a unified Microsoft Defender for Identity and Microsoft Defender for Endpoint sensor.
ms.date: 04/04/2024
ms.topic: how-to
---

# Onboard a unified Defender for Identity and Defender for Endpoint sensor (Preview)

The default Microsoft Defender for Identity architecture supports a [Defender for Identity sensor](deploy-defender-identity.md). However, Microsoft Defender for Endpoint customers can use a Defender for Endpoint sensor as a unified sensor for both Defender for Endpoint and Defender for Identity.

This article describes how to onboard a unified sensor for both Defender for Endpoint and Defender for Identity.

## Prerequisites

Before onboarding a unified sensor, make sure that your environment complies with the prerequisites in this section.

### System requirements

Unified Defender for Endpoint and Defender for Identity sensors are supported on domain controllers only, using the following operating systems only:

- Windows Server 2019
- Windows Server 2022
- [Patch level March 2024 Cumulative Update](https://support.microsoft.com/topic/march-12-2024-kb5035857-os-build-20348-2340-a7953024-bae2-4b1a-8fc1-74a17c68203c)

> [!IMPORTANT]
>After installing Patch level March 2024 Cumulative Update, LSASS might experience a memory leak on domain controllers when on-premises and cloud-based Active Directory Domain Controllers service Kerberos authentication requests.
>
> This issue is addressed in the out-of-band update KB5037422.

<!--what does this mean?-->
Supported Windows Server role is Active Directory Domain Services

Make sure that you don't have a [Defender for Identity sensor](deploy-defender-identity.md) deployed on the same domain controller as you're planning to deploy a unified sensor.

### Required permissions


To access the Defender for Identity sensor onboarding page, you must either be a [Security Administrator](/entra/identity/role-based-access-control/permissions-reference), or have the following Unified RBAC permissions:

- `Authorization and settings/Security settings/Read`
- `Authorization and settings/Security settings/All permissions`
- `Authorization and settings/System settings/Read`
- `Authorization and settings/System settings/All permissions`

For more information, see [Unified role-based access control RBAC](/defender-for-identity/role-groups#unified-role-based-access-control-rbac).

### Connectivity requirements

The unified sensor uses Defender for Endpoint URL endpoints for communication, including simplified URLs.

For more information, see [Configure your network environment to ensure connectivity with Defender for Endpoint](/microsoft-365/security/defender-endpoint/configure-environment##enable-access-to-microsoft-defender-for-endpoint-service-urls-in-the-proxy-server).

## Onboard to Defender for Endpoint

Onboard your domain controller to Defender for Endpoint as you would otherwise. For more information, see [Onboard a Windows server](/microsoft-365/security/defender-endpoint/onboard-windows-server).

## Configure Defender for Identity auditing

Defender for Identity detections rely on specific Windows Event Log entries to enhance detections and provide extra information about the users performing specific actions, such as NTLM sign-ins and security group modifications.

Configure Windows event collection to support Defender for Identity detections. For more information, see [Event collection with Microsoft Defender for Identity](event-collection-overview.md) and [Configure audit policies for Windows event logs](configure-windows-event-collection.md).

You might want to use the Defender for Identity PowerShell module to configure the required settings. For more information, see:

- [DefenderForIdentity Module](/powershell/module/defenderforidentity/)
- [Defender for Identity in the PowerShell Gallery](https://www.powershellgallery.com/packages/DefenderForIdentity/)

For example, the following command defines all settings for the domain, creates group policy objects, and links them.

```powershell
Set-MDIConfiguration -Mode Domain -Configuration All
```

## Onboard your unified sensor

Now that your environment is completely configured, onboard the unified sensor to Defender for Identity.

1. In the [Defender portal](https://security.microsoft.com), select **Settings > Identities > [Onboarding](https://security.microsoft.com/settings/identities?tabid=onboarding)**. 

    The **Onboarding** page lists any detected servers that are eligible for onboarding to Defender for Identity's unified sensor.

1. Select the server you want to onboard and select **Onboard**, and confirm your selection. 
 
When the sensor is onboarded, a green banner shows, confirming the successful onboarding. Select **Click here to see the onboarded servers** to jump to the **Settings > Identities > Sensors** page, where you can check your sensor health.

The first unified sensor that you onboard might take up to an hour to show on the **Sensors** page. Subsequent unified sensors should show within five minutes.

## Next steps

For more information, see [Manage and update Microsoft Defender for Identity sensors](../sensor-settings.md)
