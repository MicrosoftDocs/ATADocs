---
title: Event collection - Overview | Microsoft Defender for Identity
description: Learn about options for configuring extra event collection to Microsoft Defender for Identity.
ms.date: 08/10/2023
ms.topic: conceptual
---

# Event collection with Microsoft Defender for Identity

The Microsoft Defender for Identity sensor is configured to automatically collect syslog events. For Windows events, Defender for Identity detection relies on specific event logs, which the sensor parses from your domain controllers. For the correct events to be audited and included in the Windows event log, your domain controllers require accurate, advanced audit policy settings.

This article lists the events supported by the Defender for Identity sensor.

For more information, see [Configure audit policies for Windows event logs](configure-windows-event-collection.md).

## Supported AD FS events

The following events are supported for Active Directory Federation Services (AD FS) servers:

- 1202 - The Federation Service validated a new credential
- 1203 - The Federation Service failed to validate a new credential
- 4624 - An account was successfully logged on
- 4625 - An account failed to log on

For more information, see [Enable auditing on an ADFS object](configure-windows-event-collection.md#enable-auditing-on-an-adfs-object).

## Supported Active Directory Certificate Services (AD CS) events

The following events are supported for Active Directory Federation Services (AD FS) servers:

- 4870: Certificate Services revoked a certificate
- 4882: The security permissions for Certificate Services changed
- 4885: The audit filter for Certificate Services changed
- 4887: Certificate Services approved a certificate request and issued a certificate
- 4888: Certificate Services denied a certificate request
- 4890: The certificate manager settings for Certificate Services changed.
- 4896: One or more rows have been deleted from the certificate database

For more information, see [Configure auditing for AD CS](configure-windows-event-collection.md#configure-auditing-for-ad-cs).

## Other Windows events

The following general Windows events are supported for all Defender for Identity sensors:

- 1644 - LDAP search
<!--- 4662 - An operation was performed on an object-->
- 4726 - User Account Deleted
- 4728 - Member Added to Global Security Group
- 4729 - Member Removed from Global Security Group
- 4730 - Global Security Group Deleted
- 4732 - Member Added to Local Security Group
- 4733 - Member Removed from Local Security Group
- 4741 - Computer Account Added
- 4743 - Computer Account Deleted
- 4753 - Global Distribution Group Deleted
- 4756 - Member Added to Universal Security Group
- 4757 - Member Removed from Universal Security Group
- 4758 - Universal Security Group Deleted
- 4763 - Universal Distribution Group Deleted
- 4776 - Domain Controller Attempted to Validate Credentials for an Account (NTLM)
- 5136 - A directory service object was modified
- 7045 - New Service Installed
- 8004 - NTLM Authentication

> [!TIP]
> To make sure Windows Event 8004 is audited as needed by the service, review your NTLM audit settings.
>

## Event collection for standalone sensors

If you're working with a standalone Defender for Identity sensor, configure event collection manually using one of the following methods:

- [Listen for SIEM events on your Defender for Identity standalone sensor](configure-event-collection.md). Defender for Identity supports UDP traffic from your SIEM or syslog server.
- [Configure Windows event forwarding to your Defender for Identity standalone sensor](configure-event-forwarding.md)

> [!CAUTION]
> When forwarding syslog data to a standalone sensor, make sure not to forward *all* syslog data to your sensor.
>

> [!IMPORTANT]
> Defender for Identity standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the Defender for Identity sensor.

For more information, see your SIEM or syslog server's product documentation.

## Next step

> [!div class="step-by-step"]
> [Listen for SIEM events on your Defender for Identity standalone sensor  »](configure-event-collection.md)