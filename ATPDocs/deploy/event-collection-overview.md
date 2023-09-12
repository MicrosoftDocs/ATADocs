---
title: Windows event collection - Overview | Microsoft Defender for Identity
description: Learn about options for configuring Windows event collection to Microsoft Defender for Identity.
ms.date: 08/10/2023
ms.topic: conceptual
---

# What is Windows event collection for Defender for Identity?

We recommend that you enhance Microsoft Defender for Identity's detection capabilities with extra Windows events that aren't available via the domain controller network traffic.

While the Defender for Identity sensor is configured to automatically collect syslog events, if you're working with a standalone Defender for Identity sensor, you'll need to configure this manually. Using one of the following options:

- [Listen for SIEM events on your Defender for Identity standalone sensor](configure-event-collection.md)
- [Configure Windows event forwarding to your Defender for Identity standalone sensor](configure-event-forwarding.md)

When you're finished, make sure to also configure audit policies as needed. For more information, see [Configure audit policies for Windows event logs](configure-windows-event-collection.md).

> [!IMPORTANT]
> Defender for Identity standalone sensors do not support the collection of Event Tracing for Windows (ETW) log entries that provide the data for multiple detections. For full coverage of your environment, we recommend deploying the Defender for Identity sensor.


## SIEM/syslog data support

Defender for Identity supports UDP traffic from your SIEM or syslog server. If you don't use a SIEM or syslog server, configure your Windows domain controllers to forward all required events the Defender for Identity sensor for analysis. For more information, see your SIEM or syslog server's product documentation.

> [!CAUTION]
> When forwarding syslog data to a standalone sensor, make sure not to forward *all* syslog data to your sensor.
>

## NNR requirements

Network Name Resolution (NNR) is a main component of Defender for Identity functionality. To resolve IP addresses to computer names, Defender for Identity sensors look up the IP addresses using the following methods:

- NTLM over RPC (TCP Port 135).
- NetBIOS (UDP port 137).
- RDP (TCP port 3389). Only the first packet of **Client hello** queries the DNS server using reverse DNS lookup of the IP address (UDP 53)

For the first three methods to work, the relevant ports must be opened inbound from the Defender for Identity sensors to devices on the network.

## Windows Event logs

Defender for Identity detection relies on specific Windows Event logs that the sensor parses from your domain controllers. For the correct events to be audited and included in the Windows Event log, your domain controllers require accurate Advanced Audit Policy settings. For more information, see [Configure Advanced Audit Policy settings](configure-windows-event-collection.md#configure-advanced-audit-policy-settings).

To make sure Windows Event 8004 is audited as needed by the service, review your NTLM audit settings. 

> [!TIP]
> For sensors running on AD FS or AD CS servers, configure the auditing level to **Verbose**. For more information, see:
>
> - [Enable auditing on an ADFS object](configure-windows-event-collection.md#enable-auditing-on-an-adfs-object).
> - [Configure auditing for AD CS](configure-windows-event-collection.md#configure-auditing-for-ad-cs)
>
## Supported Windows events

The following Windows events are supported for the Defender for Identity sensor to collect and enhance your system's detection abilities:

- **For Active Directory Federation Services (AD FS) events**:

    - 1202 - The Federation Service validated a new credential
    - 1203 - The Federation Service failed to validate a new credential
    - 4624 - An account was successfully logged on
    - 4625 - An account failed to log on

    For more information, see [Enable auditing on an ADFS object](configure-windows-event-collection.md#enable-auditing-on-an-adfs-object).

- **For Active Directory Certificate Services (AD CS) events**:

    - 4870: Certificate Services revoked a certificate
    - 4882: The security permissions for Certificate Services changed
    - 4885: The audit filter for Certificate Services changed
    - 4887: Certificate Services approved a certificate request and issued a certificate
    - 4888: Certificate Services denied a certificate request
    - 4890: The certificate manager settings for Certificate Services changed.
    - 4896: One or more rows have been deleted from the certificate database

    For more information, see [Configure auditing for AD CS](configure-windows-event-collection.md#configure-auditing-for-ad-cs).

- **For other events**: <!--Which of these events are just for ADDS (domain controllers) and which also apply to ADFS and ADCS. -->

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

## Next step

> [!div class="step-by-step"]
> [Listen for SIEM events on your Defender for Identity standalone sensor  »](configure-event-collection.md)